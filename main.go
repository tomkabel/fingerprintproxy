package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"github.com/saucesteals/mimic"
)

const DefaultProfile = "chrome_133"
const DefaultVersion = "133.0.0.0"

const FingerprintHeader = "X-Fingerprint"
const MimicVersionHeader = "X-Mimic-Version"
const MimicBrandHeader = "X-Mimic-Brand"
const MimicPlatformHeader = "X-Mimic-Platform"

var (
	uaChromeRegex = regexp.MustCompile(`chrome/(\d+)`)
	uaEdgeRegex   = regexp.MustCompile(`edg(?:e|a)?/(\d+)`)
)

type fingerprintProxy struct {
	proxy              *goproxy.ProxyHttpServer
	mimicCache         *MimicCache
	insecureSkipVerify bool
	verbose            bool
	httpsWg            sync.WaitGroup
}

type brandPrefix struct {
	prefix string
	brand  mimic.Brand
}

var orderedBrandPrefixes = []brandPrefix{
	{"chrome_", mimic.BrandChrome},
	{"chromium_", mimic.BrandChrome},
	{"edge_", mimic.BrandEdge},
	{"brave_", mimic.BrandBrave},
	{"firefox_", mimic.BrandChrome},
	{"safari_", mimic.BrandChrome},
	{"opera_", mimic.BrandChrome},
}

func NewFingerprintProxy(verbose bool, insecureSkipVerify bool) *fingerprintProxy {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = verbose

	fp := &fingerprintProxy{
		proxy:              proxy,
		mimicCache:         NewMimicCache(defaultCacheTTL, maxCacheEntries),
		insecureSkipVerify: insecureSkipVerify,
		verbose:            verbose,
	}

	fp.setupHandlers()
	return fp
}

func (fp *fingerprintProxy) setupHandlers() {
	allHosts := regexp.MustCompile(`^.*$`)

	fp.proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			_, _ = fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}
		req.URL.Host = req.Host
		fp.proxy.ServeHTTP(w, req)
	})

	fp.proxy.OnRequest(goproxy.ReqHostMatches(allHosts)).
		HandleConnect(goproxy.AlwaysMitm)

	fp.proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		switch req.URL.Path {
		case "/__ca__":
			return fp.handleCAEndpoint(req, ctx)
		case "/__help__":
			return fp.handleHelpEndpoint(req, ctx)
		case "/__profiles__":
			return fp.handleProfilesEndpoint(req, ctx)
		}
		return fp.handleRequest(req, ctx)
	})

	fp.proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp != nil && fp.verbose {
			ctx.Logf("[Response] %d %s", resp.StatusCode, ctx.Req.URL)
		}
		return resp
	})
}

func (fp *fingerprintProxy) handleCAEndpoint(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	derBytes := goproxy.GoproxyCa.Certificate[0]
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	return req, goproxy.NewResponse(req, "application/x-x509-ca-cert", http.StatusOK, string(pemBytes))
}

func (fp *fingerprintProxy) handleHelpEndpoint(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	body := `Fingerprint Proxy v2 (mimic-based — Chromium TLS/HTTP2 emulation)

Headers:
  X-Fingerprint:       profile (chrome, edge, brave, firefox, safari, ios, chrome_120, etc.)
  X-Mimic-Version:     Chromium version (e.g. "133" or "133.0.0.0")
  X-Mimic-Brand:       "chrome", "brave", "edge"
  X-Mimic-Platform:    "win", "mac", "linux"

Note: Non-Chromium profiles (firefox, safari) fall back to Chromium emulation.

Endpoints (accessible via proxy):
  /__ca__              Download MITM CA certificate (import into Chrome)
  /__help__            This help page
  /__profiles__        List available profiles

Chrome setup:
  1. Set proxy to localhost:8080
  2. Visit http://fingerprint-proxy/__ca__ to download CA cert
  3. Import CA cert in chrome://settings/certificates (Authorities tab)
  4. Trust it for website identification
`
	return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusOK, body)
}

func (fp *fingerprintProxy) handleProfilesEndpoint(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusOK, listProfilesText())
}

func (fp *fingerprintProxy) handleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	spec := ResolveMimicSpec(req)
	ctx.Logf("[Mimic] brand=%s version=%s platform=%s", spec.Brand, spec.Version, spec.Platform)

	req.Header.Del(FingerprintHeader)
	req.Header.Del(MimicVersionHeader)
	req.Header.Del(MimicBrandHeader)
	req.Header.Del(MimicPlatformHeader)

	transport, err := fp.mimicCache.GetOrCreate(spec, fp.insecureSkipVerify)
	if err != nil {
		ctx.Logf("[Error] Failed to get mimic transport: %v", err)
		return nil, goproxy.NewResponse(req,
			goproxy.ContentTypeText,
			http.StatusInternalServerError,
			fmt.Sprintf("Mimic transport error: %v", err))
	}

	fReq, err := convertRequestToFHTTP(req)
	if err != nil {
		ctx.Logf("[Error] Request conversion failed: %v", err)
		return nil, goproxy.NewResponse(req,
			goproxy.ContentTypeText,
			http.StatusInternalServerError,
			fmt.Sprintf("Request conversion error: %v", err))
	}

	fResp, err := transport.RoundTrip(fReq)
	if err != nil {
		ctx.Logf("[Error] Round trip failed: %v", err)
		return nil, goproxy.NewResponse(req,
			goproxy.ContentTypeText,
			http.StatusBadGateway,
			fmt.Sprintf("Upstream error: %v", err))
	}

	resp, err := convertResponseFromFHTTP(fResp, req)
	if err != nil {
		ctx.Logf("[Error] Response conversion failed: %v", err)
		return nil, goproxy.NewResponse(req,
			goproxy.ContentTypeText,
			http.StatusInternalServerError,
			fmt.Sprintf("Response conversion error: %v", err))
	}

	return nil, resp
}

func ResolveMimicSpec(req *http.Request) MimicSpec {
	brand := mimic.BrandChrome
	version := DefaultVersion
	platform := mimic.PlatformWindows

	if b := req.Header.Get(MimicBrandHeader); b != "" {
		switch strings.ToLower(strings.TrimSpace(b)) {
		case "brave":
			brand = mimic.BrandBrave
		case "edge":
			brand = mimic.BrandEdge
		case "chrome", "chromium":
			brand = mimic.BrandChrome
		}
	}

	if v := req.Header.Get(MimicVersionHeader); v != "" {
		version = parseVersion(v)
	}

	if p := req.Header.Get(MimicPlatformHeader); p != "" {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "mac", "macos", "darwin":
			platform = mimic.PlatformMac
		case "linux":
			platform = mimic.PlatformLinux
		case "win", "windows":
			platform = mimic.PlatformWindows
		}
	}

	if v := req.Header.Get(FingerprintHeader); v != "" {
		spec := resolveFingerprintToMimic(strings.TrimSpace(strings.ToLower(v)))
		if spec != nil {
			brand = spec.Brand
			version = spec.Version
			platform = spec.Platform
		}
	} else {
		spec := parseUserAgentForMimic(req.Header.Get("User-Agent"))
		if spec != nil {
			brand = spec.Brand
			if spec.Version != "" {
				version = spec.Version
			}
			platform = spec.Platform
		}
	}

	return MimicSpec{Brand: brand, Version: version, Platform: platform}
}

func parseVersion(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return DefaultVersion
	}

	if !strings.Contains(v, ".") {
		if major, err := strconv.Atoi(v); err == nil {
			return strconv.Itoa(major) + ".0.0.0"
		}
		return DefaultVersion
	}

	parts := strings.SplitN(v, ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return DefaultVersion
	}
	return strconv.Itoa(major) + ".0.0.0"
}

func resolveFingerprintToMimic(fp string) *MimicSpec {
	aliasToBrand := map[string]mimic.Brand{
		"chrome":   mimic.BrandChrome,
		"chromium": mimic.BrandChrome,
		"edge":     mimic.BrandEdge,
		"brave":    mimic.BrandBrave,
		"mobile":   mimic.BrandChrome,
	}

	aliasToPlatform := map[string]mimic.Platform{
		"chrome":   mimic.PlatformWindows,
		"chromium": mimic.PlatformWindows,
		"edge":     mimic.PlatformWindows,
		"brave":    mimic.PlatformWindows,
		"mobile":   mimic.PlatformLinux,
		"firefox":  mimic.PlatformWindows,
		"ff":       mimic.PlatformWindows,
		"safari":   mimic.PlatformMac,
		"ios":      mimic.PlatformMac,
	}

	for _, bp := range orderedBrandPrefixes {
		if strings.HasPrefix(fp, bp.prefix) {
			parts := strings.SplitN(fp, "_", 2)
			version := DefaultVersion
			if len(parts) >= 2 {
				if v, err := strconv.Atoi(parts[1]); err == nil {
					version = strconv.Itoa(v) + ".0.0.0"
				}
			}
			platform := mimic.PlatformWindows
			if fp == "safari" || strings.HasPrefix(fp, "safari") || fp == "ios" || strings.HasPrefix(fp, "safari_ios") {
				platform = mimic.PlatformMac
			}
			return &MimicSpec{Brand: bp.brand, Version: version, Platform: platform}
		}
	}

	if brand, ok := aliasToBrand[fp]; ok {
		platform := mimic.PlatformWindows
		if p, ok := aliasToPlatform[fp]; ok {
			platform = p
		}
		return &MimicSpec{Brand: brand, Version: DefaultVersion, Platform: platform}
	}

	if _, ok := aliasToPlatform[fp]; ok {
		return &MimicSpec{
			Brand:    mimic.BrandChrome,
			Version:  DefaultVersion,
			Platform: aliasToPlatform[fp],
		}
	}

	return nil
}

func parseUserAgentForMimic(ua string) *MimicSpec {
	if ua == "" {
		return nil
	}
	uaLower := strings.ToLower(ua)

	spec := &MimicSpec{
		Brand:    mimic.BrandChrome,
		Version:  DefaultVersion,
		Platform: mimic.PlatformWindows,
	}

	if strings.Contains(uaLower, "linux") || strings.Contains(uaLower, "x11") {
		spec.Platform = mimic.PlatformLinux
	} else if strings.Contains(uaLower, "mac") {
		spec.Platform = mimic.PlatformMac
	}

	if strings.Contains(uaLower, "edg") || strings.Contains(uaLower, "edge") {
		spec.Brand = mimic.BrandEdge
		if m := uaEdgeRegex.FindStringSubmatch(uaLower); len(m) >= 2 {
			spec.Version = m[1] + ".0.0.0"
		}
		return spec
	}

	if strings.Contains(uaLower, "brave") {
		spec.Brand = mimic.BrandBrave
		if m := uaChromeRegex.FindStringSubmatch(uaLower); len(m) >= 2 {
			spec.Version = m[1] + ".0.0.0"
		}
		return spec
	}

	if strings.Contains(uaLower, "chrome") || strings.Contains(uaLower, "chromium") {
		spec.Brand = mimic.BrandChrome
		if m := uaChromeRegex.FindStringSubmatch(uaLower); len(m) >= 2 {
			spec.Version = m[1] + ".0.0.0"
		}
		return spec
	}

	return nil
}

func listProfilesText() string {
	var buf strings.Builder
	buf.WriteString("Fingerprint Proxy v2 — Powered by mimic (Chromium TLS/HTTP2 emulation)\n\n")
	buf.WriteString("Headers:\n")
	buf.WriteString("  X-Fingerprint:  chrome, edge, brave, chrome_120, firefox, safari, ios, mobile\n")
	buf.WriteString("  X-Mimic-Version:  Chromium major version (e.g. 133)\n")
	buf.WriteString("  X-Mimic-Brand:    chrome | brave | edge\n")
	buf.WriteString("  X-Mimic-Platform: win | mac | linux\n\n")
	buf.WriteString("Non-Chromium profiles (firefox, safari) fall back to Chrome emulation.\n")
	buf.WriteString("If no headers are set, User-Agent is parsed to auto-detect.\n")
	buf.WriteString("Fallback: Chrome 133 on Windows.\n\n")
	buf.WriteString("Supported Chromium versions: 100–137+\n\n")
	buf.WriteString("Endpoints:\n")
	buf.WriteString("  /__ca__       Download MITM CA certificate\n")
	buf.WriteString("  /__help__     This help page\n")
	return buf.String()
}

func isClosed(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

func (fp *fingerprintProxy) Handler() http.Handler {
	return fp.proxy
}

func (fp *fingerprintProxy) Run(httpAddr, httpsAddr string) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	httpServer := &http.Server{
		Addr:    httpAddr,
		Handler: fp.proxy,
	}

	go func() {
		log.Printf("[Server] HTTP proxy listening on %s", httpAddr)
		log.Printf("[Server] CA cert: visit http://127.0.0.1:8080/__ca__ via proxy to download")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Error] HTTP server error: %v", err)
		}
	}()

	ln, err := net.Listen("tcp", httpsAddr)
	if err != nil {
		return fmt.Errorf("error listening for HTTPS connections: %w", err)
	}
	log.Printf("[Server] HTTPS transparent proxy listening on %s", httpsAddr)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if isClosed(err) {
					return
				}
				select {
				case <-quit:
					return
				default:
					log.Printf("[Error] Accept error: %v", err)
					continue
				}
			}
			fp.httpsWg.Add(1)
			go func() {
				defer fp.httpsWg.Done()
				fp.handleHTTPS(c)
			}()
		}
	}()

	<-quit
	log.Printf("[Server] Shutdown signal received, stopping servers...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("[Error] HTTP server shutdown error: %v", err)
	}

	_ = ln.Close()
	fp.httpsWg.Wait()

	fp.mimicCache.CloseIdleConnections()
	log.Printf("[Server] Shutdown complete")

	return nil
}

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

func main() {
	httpAddr := flag.String("http", ":8080", "HTTP proxy listen address")
	httpsAddr := flag.String("https", ":8081", "HTTPS transparent proxy listen address")
	verbose := flag.Bool("v", false, "Enable verbose logging")
	insecureSkipVerify := flag.Bool("insecure", false, "Skip TLS certificate verification (dangerous)")
	certFile := flag.String("cert", "", "TLS certificate file for custom MITM CA")
	keyFile := flag.String("key", "", "TLS private key file for custom MITM CA")
	listHelp := flag.Bool("help", false, "Show usage and exit")
	flag.Parse()

	if *listHelp {
		fmt.Print(listProfilesText())
		os.Exit(0)
	}

	if *certFile != "" && *keyFile != "" {
		caCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("[Fatal] Failed to load custom CA: %v", err)
		}
		caCert.Leaf, _ = x509.ParseCertificate(caCert.Certificate[0])
		goproxy.GoproxyCa = caCert
		log.Printf("[Startup] Using custom CA from %s/%s", *certFile, *keyFile)
	}

	log.Printf("[Startup] Fingerprint Proxy v2 (mimic) starting...")
	log.Printf("[Startup] HTTP proxy: %s", *httpAddr)
	log.Printf("[Startup] HTTPS transparent proxy: %s", *httpsAddr)
	log.Printf("[Startup] InsecureSkipVerify: %v", *insecureSkipVerify)

	proxy := NewFingerprintProxy(*verbose, *insecureSkipVerify)

	if err := proxy.Run(*httpAddr, *httpsAddr); err != nil {
		log.Fatalf("[Fatal] Failed to start proxy: %v", err)
	}
}
