package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
)

// DefaultProfile is the profile used when no X-Fingerprint header is provided
const DefaultProfile = "chrome_133"

// Build information injected by goreleaser via ldflags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// FingerprintHeader is the header name used to specify the fingerprint profile
const FingerprintHeader = "X-Fingerprint"

// ProxyHeader is the header name used to specify the upstream proxy URL
const ProxyHeader = "X-FP-Proxy"

// Default cache TTL
const defaultCacheTTL = 30 * time.Minute

// MaxCacheEntries limits the number of cached transports
const MaxCacheEntries = 20

// allHosts matches any host for transparent proxy MITM.
var allHosts = regexp.MustCompile(`^.*$`)

// TransportCache caches fingerprint transports by profile name with TTL-based eviction.
type TransportCache struct {
	transports         map[string]*transportEntry
	mu                 sync.RWMutex
	ttl                time.Duration
	maxEntries         int
	insecureSkipVerify bool
}

type transportEntry struct {
	transport http.RoundTripper
	proxyURL  string
	created   time.Time
	lastUsed  time.Time
}

// NewTransportCache creates a new cache with the specified TTL, max entries, and TLS settings.
func NewTransportCache(ttl time.Duration, maxEntries int, insecureSkipVerify bool) *TransportCache {
	return &TransportCache{
		transports:         make(map[string]*transportEntry),
		ttl:                ttl,
		maxEntries:         maxEntries,
		insecureSkipVerify: insecureSkipVerify,
	}
}

// cacheKey generates a unique key for (profile, proxy) combination.
func cacheKey(profileName, proxyURL string) string {
	return profileName + "|" + proxyURL
}

// GetOrCreate returns a cached http.RoundTripper for the given profile name and proxy URL.
// It performs TTL-based eviction and respects maxEntries limit.
func (tc *TransportCache) GetOrCreate(profileName, proxyURL string) (http.RoundTripper, error) {
	key := cacheKey(profileName, proxyURL)

	tc.mu.Lock()
	defer tc.mu.Unlock()

	if entry, ok := tc.transports[key]; ok {
		if time.Since(entry.lastUsed) < tc.ttl {
			entry.lastUsed = time.Now()
			return entry.transport, nil
		}
		delete(tc.transports, key)
	}

	// Validate profile exists
	profile, ok := profileRegistry[profileName]
	if !ok {
		return nil, fmt.Errorf("unknown fingerprint profile: %s", profileName)
	}

	// Evict oldest entries if at capacity
	if len(tc.transports) >= tc.maxEntries {
		tc.evictOldest()
	}

	// Create new transport
	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profile),
	}
	if tc.insecureSkipVerify {
		opts = append(opts, tls_client.WithInsecureSkipVerify())
	}
	client, err := tls_client.NewHttpClient(
		tls_client.NewNoopLogger(),
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport for profile %s: %w", profileName, err)
	}

	// Apply proxy if specified
	if proxyURL != "" {
		if err := client.SetProxy(proxyURL); err != nil {
			return nil, fmt.Errorf("failed to set proxy %s for profile %s: %w", proxyURL, profileName, err)
		}
		log.Printf("[Transport] Created new transport for profile: %s with proxy: %s", profileName, proxyURL)
	} else {
		log.Printf("[Transport] Created new transport for profile: %s (no proxy)", profileName)
	}

	now := time.Now()
	tc.transports[key] = &transportEntry{
		transport: &tlsClientRoundTripper{client: client},
		proxyURL:  proxyURL,
		created:   now,
		lastUsed:  now,
	}

	return tc.transports[key].transport, nil
}

// evictOldest removes the least recently used transport from the cache.
func (tc *TransportCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range tc.transports {
		if oldestKey == "" || entry.lastUsed.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.lastUsed
		}
	}

	if oldestKey != "" {
		delete(tc.transports, oldestKey)
		log.Printf("[Transport] Evicted oldest transport: %s", oldestKey)
	}
}

// CloseIdleConnections closes idle connections on all cached transports.
func (tc *TransportCache) CloseIdleConnections() {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	for _, entry := range tc.transports {
		if closer, ok := entry.transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

// Len returns the number of cached transports.
func (tc *TransportCache) Len() int {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return len(tc.transports)
}

var profileAliases = map[string]string{
	"chrome":   "chrome_133",
	"chromium": "chrome_133",
	"firefox":  "firefox_147",
	"ff":       "firefox_147",
	"safari":   "safari_16_0",
	"ios":      "safari_ios_18_5",
	"mobile":   "chrome_133",
	"edge":     "chrome_133",
}

// resolveProfileAlias handles common profile name variations
func resolveProfileAlias(alias string) string {
	if resolved, ok := profileAliases[alias]; ok {
		return resolved
	}
	return alias
}

// GetProfileFromRequest extracts the fingerprint profile name from the request,
// falling back to the given default if none is specified or the header value is invalid.
func GetProfileFromRequest(req *http.Request, defaultProfile string) (profileName string, isFallback bool) {
	if fp := req.Header.Get(FingerprintHeader); fp != "" {
		fp = strings.TrimSpace(strings.ToLower(fp))
		if GetProfile(fp) != nil {
			return fp, false
		}
		aliased := resolveProfileAlias(fp)
		if GetProfile(aliased) != nil {
			return aliased, false
		}
		log.Printf("[Warning] Invalid X-Fingerprint profile: %s, falling back", fp)
	}
	return defaultProfile, true
}

// GetProxyFromRequest extracts the upstream proxy URL from the request.
func GetProxyFromRequest(req *http.Request) string {
	return strings.TrimSpace(req.Header.Get(ProxyHeader))
}

// fingerprintRoundTripperWrapper wraps an http.RoundTripper to implement goproxy's RoundTripper interface.
type fingerprintRoundTripperWrapper struct {
	rt http.RoundTripper
}

func (w *fingerprintRoundTripperWrapper) RoundTrip(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	return w.rt.RoundTrip(ctx.Req)
}

// tlsClientRoundTripper wraps tls_client.HttpClient to implement http.RoundTripper.
// tls-client internally uses fhttp (aliased as http), so we must convert
// between net/http and fhttp types on every request/response.
type tlsClientRoundTripper struct {
	client tls_client.HttpClient
}

func (t *tlsClientRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	fhttpReq, err := netHttpRequestToFhttp(req)
	if err != nil {
		return nil, err
	}
	fhttpResp, err := t.client.Do(fhttpReq)
	if err != nil {
		return nil, err
	}
	return fhttpResponseToNetHttp(fhttpResp), nil
}

func (t *tlsClientRoundTripper) CloseIdleConnections() {
	t.client.CloseIdleConnections()
}

func (t *tlsClientRoundTripper) SetProxy(proxyURL string) error {
	return t.client.SetProxy(proxyURL)
}

// netHttpRequestToFhttp converts a net/http.Request to an fhttp.Request.
func netHttpRequestToFhttp(req *http.Request) (*fhttp.Request, error) {
	if req.URL == nil {
		return nil, fmt.Errorf("request has nil URL")
	}

	freq, err := fhttp.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create fhttp request: %w", err)
	}

	freq.Header = fhttp.Header(req.Header.Clone())
	freq.Host = req.Host
	freq.ContentLength = req.ContentLength
	freq.Close = req.Close

	if req.GetBody != nil {
		freq.GetBody = func() (io.ReadCloser, error) {
			return req.GetBody()
		}
	}

	return freq, nil
}

// fhttpResponseToNetHttp converts an fhttp.Response to a net/http.Response.
func fhttpResponseToNetHttp(fresp *fhttp.Response) *http.Response {
	return &http.Response{
		Status:           fresp.Status,
		StatusCode:       fresp.StatusCode,
		Proto:            fresp.Proto,
		ProtoMajor:       fresp.ProtoMajor,
		ProtoMinor:       fresp.ProtoMinor,
		Header:           http.Header(fresp.Header.Clone()),
		Body:             fresp.Body,
		ContentLength:    fresp.ContentLength,
		TransferEncoding: fresp.TransferEncoding,
		Close:            fresp.Close,
		Uncompressed:     fresp.Uncompressed,
		Trailer:          http.Header(fresp.Trailer.Clone()),
		Request:          netHttpRequestFromFhttp(fresp.Request),
	}
}

func netHttpRequestFromFhttp(freq *fhttp.Request) *http.Request {
	if freq == nil {
		return nil
	}
	return &http.Request{
		Method:           freq.Method,
		URL:              freq.URL,
		Proto:            freq.Proto,
		ProtoMajor:       freq.ProtoMajor,
		ProtoMinor:       freq.ProtoMinor,
		Header:           http.Header(freq.Header.Clone()),
		Body:             freq.Body,
		ContentLength:    freq.ContentLength,
		TransferEncoding: freq.TransferEncoding,
		Close:            freq.Close,
		Host:             freq.Host,
		RemoteAddr:       freq.RemoteAddr,
		RequestURI:       freq.RequestURI,
	}
}

// fingerprintProxy is the main proxy structure
type fingerprintProxy struct {
	proxy              *goproxy.ProxyHttpServer
	transportCache     *TransportCache
	verbose            bool
	defaultProfile     string
	insecureSkipVerify bool
	httpAddr           string
	httpsAddr          string
	connWg             sync.WaitGroup
}

// NewFingerprintProxy creates a new fingerprint proxy with configurable options.
func NewFingerprintProxy(verbose bool, defaultProfile string, insecureSkipVerify bool, cacheTTL time.Duration, cacheMaxEntries int) *fingerprintProxy {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = verbose

	fp := &fingerprintProxy{
		proxy:              proxy,
		transportCache:     NewTransportCache(cacheTTL, cacheMaxEntries, insecureSkipVerify),
		verbose:            verbose,
		defaultProfile:     defaultProfile,
		insecureSkipVerify: insecureSkipVerify,
	}

	fp.setupHandlers(defaultProfile)
	return fp
}

// setupHandlers configures the goproxy request handlers using the given default profile.
func (fp *fingerprintProxy) setupHandlers(defaultProfile string) {
	// Non-proxy handler for transparent mode
	fp.proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			_, _ = fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		fp.proxy.ServeHTTP(w, req)
	})

	// Always MITM for transparent proxy
	fp.proxy.OnRequest(goproxy.ReqHostMatches(allHosts)).
		HandleConnect(goproxy.AlwaysMitm)

	// Main request handler
	fp.proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		profileName, isFallback := GetProfileFromRequest(req, fp.defaultProfile)
		proxyURL := GetProxyFromRequest(req)

		if isFallback {
			ctx.Logf("[Fingerprint] Using fallback profile: %s (no X-Fingerprint header)", profileName)
		} else {
			ctx.Logf("[Fingerprint] Using X-Fingerprint profile: %s", profileName)
		}

		if proxyURL != "" {
			ctx.Logf("[Proxy] Using upstream proxy: %s", proxyURL)
		}

		transport, err := fp.transportCache.GetOrCreate(profileName, proxyURL)
		if err != nil {
			ctx.Logf("[Error] Failed to get transport for profile %s: %v", profileName, err)
			return nil, goproxy.NewResponse(req,
				goproxy.ContentTypeText,
				http.StatusInternalServerError,
				fmt.Sprintf("Fingerprint error: %v", err))
		}

		ctx.RoundTripper = &fingerprintRoundTripperWrapper{rt: transport}
		req.Header.Del(FingerprintHeader)
		req.Header.Del(ProxyHeader)

		return req, nil
	})

	fp.proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp != nil && fp.verbose {
			ctx.Logf("[Response] %d %s", resp.StatusCode, ctx.Req.URL)
		}
		return resp
	})
}

// Handler returns the HTTP handler for the proxy
func (fp *fingerprintProxy) Handler() http.Handler {
	return fp.proxy
}

// Run starts the proxy server with graceful shutdown support.
func (fp *fingerprintProxy) Run(httpAddr, httpsAddr string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup

	httpServer := &http.Server{
		Addr:    httpAddr,
		Handler: fp.proxy,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("[Server] HTTP proxy listening on %s", httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Error] HTTP server error: %v", err)
		}
	}()

	ln, err := net.Listen("tcp", httpsAddr)
	if err != nil {
		stop()
		return fmt.Errorf("error listening for HTTPS connections: %w", err)
	}
	log.Printf("[Server] HTTPS transparent proxy listening on %s", httpsAddr)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Printf("[Error] Accept error: %v", err)
					continue
				}
			}
			fp.connWg.Add(1)
			go func() {
				defer fp.connWg.Done()
				fp.handleHTTPS(c)
			}()
		}
	}()

	<-ctx.Done()
	log.Printf("[Server] Shutdown signal received, stopping servers...")

	_ = ln.Close()

	done := make(chan struct{})
	go func() {
		fp.connWg.Wait()
		close(done)
	}()
	select {
	case <-done:
		log.Printf("[Server] All HTTPS connections drained")
	case <-time.After(10 * time.Second):
		log.Printf("[Server] Timed out waiting for HTTPS connections to drain")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("[Error] HTTP server shutdown error: %v", err)
	}
	_ = ln.Close()

	wg.Wait()

	fp.transportCache.CloseIdleConnections()
	log.Printf("[Server] Shutdown complete")
	return nil
}

// handleHTTPS handles an incoming HTTPS connection
func (fp *fingerprintProxy) handleHTTPS(c net.Conn) {
	defer c.Close()

	tlsConn, err := vhost.TLS(c)
	if err != nil {
		log.Printf("[Error] TLS vhost error: %v", err)
		return
	}

	if tlsConn.Host() == "" {
		log.Printf("[Warning] Cannot support non-SNI enabled clients from %s", c.RemoteAddr())
		return
	}

	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Opaque: tlsConn.Host(),
			Host:   net.JoinHostPort(tlsConn.Host(), "443"),
		},
		Host:       tlsConn.Host(),
		Header:     make(http.Header),
		RemoteAddr: c.RemoteAddr().String(),
	}

	resp := &dumbResponseWriter{Conn: tlsConn}
	fp.proxy.ServeHTTP(resp, connectReq)
}

type dumbResponseWriter struct {
	net.Conn
	header          http.Header
	connectBuf      bytes.Buffer
	headerSent      bool
	connectComplete bool
	statusCode      int
}

func (dumb *dumbResponseWriter) Header() http.Header {
	if dumb.header == nil {
		dumb.header = make(http.Header)
	}
	return dumb.header
}

func (dumb *dumbResponseWriter) Write(buf []byte) (int, error) {
	if dumb.connectComplete {
		return dumb.Conn.Write(buf)
	}
	if !dumb.headerSent || dumb.statusCode != http.StatusOK {
		return dumb.Conn.Write(buf)
	}
	dumb.connectBuf.Write(buf)
	if bytes.Index(dumb.connectBuf.Bytes(), []byte("\r\n\r\n")) >= 0 {
		dumb.connectComplete = true
		dumb.connectBuf.Reset()
	}
	return len(buf), nil
}

func (dumb *dumbResponseWriter) WriteHeader(code int) {
	dumb.headerSent = true
	dumb.statusCode = code
}

func (dumb *dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func listProfiles() {
	fmt.Println("Available fingerprint profiles:")
	for _, name := range ListProfiles() {
		profile := GetProfile(name)
		if profile != nil {
			fmt.Printf("  %-20s - %s (HTTP/3: %v, PSK: %v)\n",
				name,
				profile.Name(),
				profile.SupportsHTTP3(),
				profile.SupportsPSK(),
			)
		}
	}
	fmt.Printf("\nDefault profile: %s\n", DefaultProfile)
	fmt.Println("\nYou can also use aliases: chrome, firefox, safari, edge, etc.")
	fmt.Println("\nRequest headers for routing:")
	fmt.Println("  X-Fingerprint: Specify fingerprint profile (e.g., chrome_133, firefox_147)")
	fmt.Println("  X-FP-Proxy:    Specify upstream proxy (e.g., socks5://user:pass@host:port or http://user:pass@host:port)")
}

func main() {
	httpAddr := flag.String("http", ":8080", "HTTP proxy listen address")
	httpsAddr := flag.String("https", ":8081", "HTTPS transparent proxy listen address")
	profile := flag.String("profile", DefaultProfile, "Default fingerprint profile")
	verbose := flag.Bool("v", false, "Enable verbose logging")
	cacheTTL := flag.Duration("cache-ttl", defaultCacheTTL, "Transport cache TTL (e.g., 30m, 1h)")
	cacheMaxEntries := flag.Int("cache-max", MaxCacheEntries, "Maximum cached transports")
	insecureSkipVerify := flag.Bool("insecure", false, "Skip TLS certificate verification (dangerous, for testing only)")
	listProfilesFlag := flag.Bool("list", false, "List available fingerprint profiles and exit")
	flag.Parse()

	if *listProfilesFlag {
		listProfiles()
		os.Exit(0)
	}

	if GetProfile(*profile) == nil {
		fmt.Printf("Error: Invalid default profile: %s\n", *profile)
		fmt.Println("Use -list to see available profiles")
		os.Exit(1)
	}

	log.Printf("[Startup] Fingerprint Proxy %s (commit: %s, built: %s)", version, commit, date)
	log.Printf("[Startup] Default profile: %s", *profile)
	log.Printf("[Startup] HTTP proxy: %s", *httpAddr)
	log.Printf("[Startup] HTTPS transparent proxy: %s", *httpsAddr)
	log.Printf("[Startup] Cache TTL: %v, max entries: %d", *cacheTTL, *cacheMaxEntries)
	log.Printf("[Startup] InsecureSkipVerify: %v", *insecureSkipVerify)

	proxy := NewFingerprintProxy(*verbose, *profile, *insecureSkipVerify, *cacheTTL, *cacheMaxEntries)

	if err := proxy.Run(*httpAddr, *httpsAddr); err != nil {
		log.Fatalf("[Fatal] Failed to start proxy: %v", err)
	}
}
