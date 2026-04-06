package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
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

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	fingerprints "github.com/tomkabel/browser-fingerprint-transport"
)

// DefaultProfile is the profile used when no X-Fingerprint header is provided
const DefaultProfile = "chrome_133"

// FingerprintHeader is the header name used to specify the fingerprint profile
const FingerprintHeader = "X-Fingerprint"

// Default cache TTL
const defaultCacheTTL = 30 * time.Minute

// MaxCacheEntries limits the number of cached transports
const MaxCacheEntries = 20

// TransportCache caches fingerprint transports by profile name with TTL-based eviction.
type TransportCache struct {
	transports map[string]*transportEntry
	mu         sync.RWMutex
	ttl        time.Duration
	maxEntries int
}

type transportEntry struct {
	transport http.RoundTripper
	created   time.Time
	lastUsed  time.Time
}

// NewTransportCache creates a new cache with the specified TTL and max entries.
func NewTransportCache(ttl time.Duration, maxEntries int) *TransportCache {
	return &TransportCache{
		transports: make(map[string]*transportEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

// GetOrCreate returns a cached http.RoundTripper for the given profile name.
// It performs TTL-based eviction and respects maxEntries limit.
func (tc *TransportCache) GetOrCreate(profileName string) (http.RoundTripper, error) {
	// Check if already cached and valid (fast path with read lock)
	tc.mu.RLock()
	if entry, ok := tc.transports[profileName]; ok {
		if time.Since(entry.lastUsed) < tc.ttl {
			entry.lastUsed = time.Now()
			tc.mu.RUnlock()
			return entry.transport, nil
		}
		// Entry expired, will be evicted (but we need write lock for deletion)
	}
	tc.mu.RUnlock()

	// Slow path: create new transport with write lock
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Double-check after acquiring write lock
	if entry, ok := tc.transports[profileName]; ok {
		if time.Since(entry.lastUsed) < tc.ttl {
			entry.lastUsed = time.Now()
			return entry.transport, nil
		}
		// Expired, remove it
		delete(tc.transports, profileName)
	}

	// Validate profile exists
	profile := fingerprints.GetProfile(profileName)
	if profile == nil {
		return nil, fmt.Errorf("unknown fingerprint profile: %s", profileName)
	}

	// Evict oldest entries if at capacity
	if len(tc.transports) >= tc.maxEntries {
		tc.evictOldest()
	}

	// Create new transport
	config := fingerprints.NewConfig(
		fingerprints.WithProfile(profile),
	)

	transport, err := fingerprints.NewFingerprintRoundTripper(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport for profile %s: %w", profileName, err)
	}

	now := time.Now()
	tc.transports[profileName] = &transportEntry{
		transport: transport,
		created:   now,
		lastUsed:  now,
	}

	log.Printf("[Transport] Created new transport for profile: %s", profileName)
	return transport, nil
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

// resolveProfileAlias handles common profile name variations
func resolveProfileAlias(alias string) string {
	aliases := map[string]string{
		"chrome":   "chrome_133",
		"chromium": "chrome_133",
		"firefox":  "firefox_147",
		"ff":       "firefox_147",
		"safari":   "safari_18_5",
		"ios":      "safari_ios_18_5",
		"mobile":   "chrome_133",
		"edge":     "chrome_133",
	}

	if resolved, ok := aliases[alias]; ok {
		return resolved
	}
	return alias
}

// GetProfileFromRequest extracts the fingerprint profile name from the request.
func GetProfileFromRequest(req *http.Request) (profileName string, isFallback bool) {
	// Try X-Fingerprint header first
	if fp := req.Header.Get(FingerprintHeader); fp != "" {
		fp = strings.TrimSpace(strings.ToLower(fp))
		if fingerprints.GetProfile(fp) != nil {
			return fp, false
		}
		aliased := resolveProfileAlias(fp)
		if fingerprints.GetProfile(aliased) != nil {
			return aliased, false
		}
		log.Printf("[Warning] Invalid X-Fingerprint profile: %s, falling back", fp)
	}

	// Fall back to default
	return DefaultProfile, true
}

// fingerprintRoundTripperWrapper wraps an http.RoundTripper to implement goproxy's RoundTripper interface.
type fingerprintRoundTripperWrapper struct {
	rt http.RoundTripper
}

func (w *fingerprintRoundTripperWrapper) RoundTrip(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	// Create a new request with context to support cancellation
	newReq := req.WithContext(ctx.Req.Context())
	return w.rt.RoundTrip(newReq)
}

// fingerprintProxy is the main proxy structure
type fingerprintProxy struct {
	proxy          *goproxy.ProxyHttpServer
	transportCache *TransportCache
	verbose        bool
	certFile       string
	keyFile        string
}

// NewFingerprintProxy creates a new fingerprint proxy with configurable options.
func NewFingerprintProxy(verbose bool, certFile, keyFile string) *fingerprintProxy {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = verbose

	fp := &fingerprintProxy{
		proxy:          proxy,
		transportCache: NewTransportCache(defaultCacheTTL, MaxCacheEntries),
		verbose:        verbose,
		certFile:       certFile,
		keyFile:        keyFile,
	}

	fp.setupHandlers()
	return fp
}

// setupHandlers configures the goproxy request handlers
func (fp *fingerprintProxy) setupHandlers() {
	// Compile regex once
	allHosts := regexp.MustCompile(`^.*$`)

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
		profileName, isFallback := GetProfileFromRequest(req)

		if isFallback {
			ctx.Logf("[Fingerprint] Using fallback profile: %s (no X-Fingerprint header)", profileName)
		} else {
			ctx.Logf("[Fingerprint] Using X-Fingerprint profile: %s", profileName)
		}

		transport, err := fp.transportCache.GetOrCreate(profileName)
		if err != nil {
			ctx.Logf("[Error] Failed to get transport for profile %s: %v", profileName, err)
			return nil, goproxy.NewResponse(req,
				goproxy.ContentTypeText,
				http.StatusInternalServerError,
				fmt.Sprintf("Fingerprint error: %v", err))
		}

		ctx.RoundTripper = &fingerprintRoundTripperWrapper{rt: transport}
		req.Header.Del(FingerprintHeader)

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
	// Channel to receive shutdown signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// HTTP server
	httpServer := &http.Server{
		Addr:    httpAddr,
		Handler: fp.proxy,
	}

	// Start HTTP server in goroutine
	go func() {
		log.Printf("[Server] HTTP proxy listening on %s", httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Error] HTTP server error: %v", err)
		}
	}()

	// HTTPS listener
	ln, err := net.Listen("tcp", httpsAddr)
	if err != nil {
		return fmt.Errorf("error listening for HTTPS connections: %w", err)
	}
	log.Printf("[Server] HTTPS transparent proxy listening on %s", httpsAddr)

	// Goroutine to accept HTTPS connections
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-quit:
					return
				default:
					log.Printf("[Error] Accept error: %v", err)
					continue
				}
			}
			go fp.handleHTTPS(c)
		}
	}()

	// Wait for shutdown signal
	<-quit
	log.Printf("[Server] Shutdown signal received, stopping servers...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("[Error] HTTP server shutdown error: %v", err)
	}

	// Close HTTPS listener
	_ = ln.Close()

	// Close idle connections in cache
	fp.transportCache.CloseIdleConnections()
	log.Printf("[Server] Shutdown complete")

	return nil
}

// handleHTTPS handles an incoming HTTPS connection
func (fp *fingerprintProxy) handleHTTPS(c net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Error] panic in handleHTTPS: %v", r)
		}
		_ = c.Close()
	}()

	tlsConn, err := vhost.TLS(c)
	if err != nil {
		log.Printf("[Error] TLS vhost error: %v", err)
		return
	}

	if tlsConn.Host() == "" {
		log.Printf("[Warning] Cannot support non-SNI enabled clients")
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
}

func (dumb *dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb *dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil
	}
	return dumb.Conn.Write(buf)
}

func (dumb *dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb *dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func listProfiles() {
	fmt.Println("Available fingerprint profiles:")
	for _, name := range fingerprints.ListProfiles() {
		profile := fingerprints.GetProfile(name)
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
}

func main() {
	httpAddr := flag.String("http", ":8080", "HTTP proxy listen address")
	httpsAddr := flag.String("https", ":8081", "HTTPS transparent proxy listen address")
	profile := flag.String("profile", DefaultProfile, "Default fingerprint profile")
	verbose := flag.Bool("v", true, "Enable verbose logging")
	insecureSkipVerify := flag.Bool("insecure", false, "Skip TLS certificate verification (dangerous, for testing only)")
	certFile := flag.String("cert", "", "TLS certificate file (for MITM)")
	keyFile := flag.String("key", "", "TLS private key file")
	listProfilesFlag := flag.Bool("list", false, "List available fingerprint profiles and exit")
	flag.Parse()

	if *listProfilesFlag {
		listProfiles()
		os.Exit(0)
	}

	if fingerprints.GetProfile(*profile) == nil {
		fmt.Printf("Error: Invalid default profile: %s\n", *profile)
		fmt.Println("Use -list to see available profiles")
		os.Exit(1)
	}

	log.Printf("[Startup] Fingerprint Proxy starting...")
	log.Printf("[Startup] Default profile: %s", *profile)
	log.Printf("[Startup] HTTP proxy: %s", *httpAddr)
	log.Printf("[Startup] HTTPS transparent proxy: %s", *httpsAddr)
	log.Printf("[Startup] InsecureSkipVerify: %v", *insecureSkipVerify)

	proxy := NewFingerprintProxy(*verbose, *certFile, *keyFile)

	if err := proxy.Run(*httpAddr, *httpsAddr); err != nil {
		log.Fatalf("[Fatal] Failed to start proxy: %v", err)
	}
}
