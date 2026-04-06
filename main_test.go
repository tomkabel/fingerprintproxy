package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	fingerprints "github.com/tomkabel/browser-fingerprint-transport"
)

// --- TestGetProfileFromRequest ---

func TestGetProfileFromRequest(t *testing.T) {
	tests := []struct {
		name            string
		headers         map[string]string
		expectedProfile string
		expectFallback  bool
	}{
		{name: "X-Fingerprint header with valid profile", headers: map[string]string{"X-Fingerprint": "chrome_133"}, expectedProfile: "chrome_133", expectFallback: false},
		{name: "X-Fingerprint header with firefox", headers: map[string]string{"X-Fingerprint": "firefox_147"}, expectedProfile: "firefox_147", expectFallback: false},
		{name: "X-Fingerprint header with safari_ios", headers: map[string]string{"X-Fingerprint": "safari_ios_18_5"}, expectedProfile: "safari_ios_18_5", expectFallback: false},
		{name: "X-Fingerprint header with chrome alias", headers: map[string]string{"X-Fingerprint": "chrome"}, expectedProfile: "chrome_133", expectFallback: false},
		{name: "X-Fingerprint header with firefox alias", headers: map[string]string{"X-Fingerprint": "firefox"}, expectedProfile: "firefox_147", expectFallback: false},
		{name: "X-Fingerprint header with case insensitive", headers: map[string]string{"X-Fingerprint": "FIREFOX_147"}, expectedProfile: "firefox_147", expectFallback: false},
		{name: "X-Fingerprint header with spaces", headers: map[string]string{"X-Fingerprint": "  chrome_133  "}, expectedProfile: "chrome_133", expectFallback: false},
		{name: "No X-Fingerprint header returns default", headers: map[string]string{}, expectedProfile: DefaultProfile, expectFallback: true},
		{name: "Invalid X-Fingerprint falls back to default", headers: map[string]string{"X-Fingerprint": "invalid_profile"}, expectedProfile: DefaultProfile, expectFallback: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			profile, isFallback := GetProfileFromRequest(req)

			if profile != tt.expectedProfile {
				t.Errorf("expected profile %s, got %s", tt.expectedProfile, profile)
			}

			if isFallback != tt.expectFallback {
				t.Errorf("expected fallback %v, got %v", tt.expectFallback, isFallback)
			}
		})
	}
}

// --- TestResolveProfileAlias ---

func TestResolveProfileAlias(t *testing.T) {
	tests := []struct {
		alias    string
		expected string
	}{
		{"chrome", "chrome_133"},
		{"chromium", "chrome_133"},
		{"firefox", "firefox_147"},
		{"ff", "firefox_147"},
		{"safari", "safari_18_5"},
		{"ios", "safari_ios_18_5"},
		{"mobile", "chrome_133"},
		{"edge", "chrome_133"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.alias, func(t *testing.T) {
			result := resolveProfileAlias(tt.alias)
			if result != tt.expected {
				t.Errorf("resolveProfileAlias(%s) = %s, want %s", tt.alias, result, tt.expected)
			}
		})
	}
}

// --- TestTransportCache ---

func TestTransportCache(t *testing.T) {
	// Create cache with short TTL for testing
	cache := NewTransportCache(100*time.Millisecond, 10)

	t.Run("creates transport on first call", func(t *testing.T) {
		transport, err := cache.GetOrCreate("chrome_133")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if transport == nil {
			t.Fatal("expected non-nil transport")
		}
	})

	t.Run("returns cached transport on second call", func(t *testing.T) {
		transport1, _ := cache.GetOrCreate("chrome_133")
		transport2, _ := cache.GetOrCreate("chrome_133")

		if transport1 != transport2 {
			t.Error("expected same transport instance for same profile")
		}
	})

	t.Run("creates different transport for different profile", func(t *testing.T) {
		transport1, _ := cache.GetOrCreate("chrome_133")
		transport2, _ := cache.GetOrCreate("firefox_147")

		if transport1 == transport2 {
			t.Error("expected different transport instances for different profiles")
		}
	})

	t.Run("returns error for invalid profile", func(t *testing.T) {
		_, err := cache.GetOrCreate("invalid_profile")
		if err == nil {
			t.Error("expected error for invalid profile")
		}
	})

	t.Run("evicts expired entries", func(t *testing.T) {
		cacheTTL := 50 * time.Millisecond
		cacheEvict := NewTransportCache(cacheTTL, 10)

		// Create a transport
		_, err := cacheEvict.GetOrCreate("chrome_133")
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}

		// Wait for TTL to expire
		time.Sleep(cacheTTL + 10*time.Millisecond)

		// Should create a new transport (old one evicted)
		transport, err := cacheEvict.GetOrCreate("chrome_133")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if transport == nil {
			t.Fatal("expected non-nil transport after eviction")
		}
	})

	t.Run("respects max entries limit", func(t *testing.T) {
		cacheLimited := NewTransportCache(time.Hour, 2)

		// Create two transports
		_, err := cacheLimited.GetOrCreate("chrome_133")
		if err != nil {
			t.Fatalf("failed to create chrome_133: %v", err)
		}
		_, err = cacheLimited.GetOrCreate("firefox_147")
		if err != nil {
			t.Fatalf("failed to create firefox_147: %v", err)
		}

		// Cache should be at limit
		if cacheLimited.Len() != 2 {
			t.Errorf("expected cache length 2, got %d", cacheLimited.Len())
		}

		// Creating a third should evict oldest
		_, err = cacheLimited.GetOrCreate("safari_ios_18_5")
		if err != nil {
			t.Fatalf("failed to create safari_ios_18_5: %v", err)
		}

		// Cache should still be at limit
		if cacheLimited.Len() != 2 {
			t.Errorf("expected cache length 2 after eviction, got %d", cacheLimited.Len())
		}
	})
}

// --- TestTransportCacheCloseIdleConnections ---

func TestTransportCacheCloseIdleConnections(t *testing.T) {
	cache := NewTransportCache(time.Hour, 10)

	// Create some transports
	_, err := cache.GetOrCreate("chrome_133")
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}

	// Should not panic
	cache.CloseIdleConnections()
}

// --- TestFingerprintRoundTripperWrapper ---

func TestFingerprintRoundTripperWrapper(t *testing.T) {
	mockTransport := &mockRoundTripper{
		response: &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("OK")),
		},
	}

	wrapper := &fingerprintRoundTripperWrapper{rt: mockTransport}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	resp, err := wrapper.RoundTrip(req, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestFingerprintRoundTripperWrapperContextCancellation(t *testing.T) {
	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	mockTransport := &mockRoundTripper{
		response: nil,
		err:      context.Canceled,
	}

	wrapper := &fingerprintRoundTripperWrapper{rt: mockTransport}

	req := httptest.NewRequest("GET", "http://example.com", nil).WithContext(ctx)
	ctxProxy := &goproxy.ProxyCtx{Req: req}

	_, err := wrapper.RoundTrip(req, ctxProxy)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

type mockRoundTripper struct {
	response *http.Response
	err      error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.response, m.err
}

// --- TestDumbResponseWriter ---

func TestDumbResponseWriter(t *testing.T) {
	mockConn := &mockConn{}

	w := &dumbResponseWriter{Conn: mockConn}

	// Test Write with HTTP OK response (should be discarded)
	n, err := w.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len("HTTP/1.0 200 OK\r\n\r\n") {
		t.Errorf("expected %d bytes written, got %d", len("HTTP/1.0 200 OK\r\n\r\n"), n)
	}

	// Test Write with regular data
	data := []byte("Hello, World!")
	n, err = w.Write(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}

	// Test that Header panics
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic from Header()")
			}
		}()
		w.Header()
	}()

	// Test that WriteHeader panics
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic from WriteHeader()")
			}
		}()
		w.WriteHeader(200)
	}()

	// Test Hijack
	conn, bufioRW, err := w.Hijack()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Error("expected non-nil connection from Hijack")
	}
	if bufioRW == nil {
		t.Error("expected non-nil bufio.ReadWriter from Hijack")
	}
}

type mockConn struct {
	readData []byte
	writeMu  sync.Mutex
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if len(m.readData) == 0 {
		return 0, io.EOF
	}
	n = copy(b, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.readData = append(m.readData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// --- PeetAPIResponse ---

type PeetAPIResponse struct {
	IP          string `json:"ip"`
	HTTPVersion string `json:"http_version"`
	UserAgent   string `json:"user_agent"`
	TLS         struct {
		JA3     string `json:"ja3"`
		JA3Hash string `json:"ja3_hash"`
		JA4     string `json:"ja4"`
		JA4R    string `json:"ja4_r"`
	} `json:"tls"`
	HTTP2 struct {
		AkamaiFingerprint string `json:"akamai_fingerprint"`
	} `json:"http2"`
}

// --- Known JA3 hashes for verification ---

var knownFingerprints = map[string]string{
	"chrome_133":  "74e530e488a43fddd78be75918be78c7", // Known Chrome 133 JA3 hash
	"firefox_147": "6f7889b9fb1a62a9577e685c1fcfa919", // Known Firefox 147 JA3 hash
}

// --- Integration Tests ---

func TestChromeFingerprintAgainstAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	proxy := newTestFingerprintProxy()

	transport, err := proxy.transportCache.GetOrCreate("chrome_133")
	if err != nil {
		t.Fatalf("failed to get Chrome transport: %v", err)
	}

	req := httptest.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	var apiResp PeetAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	t.Logf("API Response JA3: %s", apiResp.TLS.JA3)
	t.Logf("API Response JA3 Hash: %s", apiResp.TLS.JA3Hash)
	t.Logf("API Response JA4: %s", apiResp.TLS.JA4)
	t.Logf("API Response HTTP Version: %s", apiResp.HTTPVersion)

	// Assert JA3 hash matches known fingerprint for Chrome 133
	if expectedHash, ok := knownFingerprints["chrome_133"]; ok {
		if apiResp.TLS.JA3Hash != expectedHash {
			t.Errorf("Chrome JA3 hash mismatch:\n  expected: %s\n  got:      %s", expectedHash, apiResp.TLS.JA3Hash)
		}
	}

	// Assert HTTP/2 is used
	if apiResp.HTTPVersion != "h2" {
		t.Errorf("expected HTTP/2, got %s", apiResp.HTTPVersion)
	}
}

func TestFirefoxFingerprintAgainstAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	proxy := newTestFingerprintProxy()

	transport, err := proxy.transportCache.GetOrCreate("firefox_147")
	if err != nil {
		t.Fatalf("failed to get Firefox transport: %v", err)
	}

	req := httptest.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	var apiResp PeetAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	t.Logf("API Response JA3: %s", apiResp.TLS.JA3)
	t.Logf("API Response JA3 Hash: %s", apiResp.TLS.JA3Hash)
	t.Logf("API Response JA4: %s", apiResp.TLS.JA4)
	t.Logf("API Response HTTP Version: %s", apiResp.HTTPVersion)

	// Assert JA3 hash matches known fingerprint for Firefox 147
	if expectedHash, ok := knownFingerprints["firefox_147"]; ok {
		if apiResp.TLS.JA3Hash != expectedHash {
			t.Errorf("Firefox JA3 hash mismatch:\n  expected: %s\n  got:      %s", expectedHash, apiResp.TLS.JA3Hash)
		}
	}

	// Assert HTTP/2 is used
	if apiResp.HTTPVersion != "h2" {
		t.Errorf("expected HTTP/2, got %s", apiResp.HTTPVersion)
	}
}

// --- Helper ---

func newTestFingerprintProxy() *fingerprintProxy {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	fp := &fingerprintProxy{
		proxy:          proxy,
		transportCache: NewTransportCache(time.Hour, 10),
		verbose:        false,
	}

	fp.setupHandlers()
	return fp
}

// --- TestFingerprintHeaderRouting ---

func TestFingerprintHeaderRouting(t *testing.T) {
	testCases := []struct {
		header   string
		expected string
	}{
		{"chrome_133", "chrome_133"},
		{"firefox_147", "firefox_147"},
		{"safari_ios_18_5", "safari_ios_18_5"},
	}

	for _, tc := range testCases {
		t.Run(tc.header, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.Header.Set("X-Fingerprint", tc.header)

			profile, _ := GetProfileFromRequest(req)
			if profile != tc.expected {
				t.Errorf("expected profile %s, got %s", tc.expected, profile)
			}
		})
	}
}

// --- TestInvalidProfileHandling ---

func TestInvalidProfileHandling(t *testing.T) {
	cache := NewTransportCache(time.Hour, 10)

	_, err := cache.GetOrCreate("nonexistent_profile_xyz")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}

	if !strings.Contains(err.Error(), "unknown fingerprint profile") {
		t.Errorf("expected 'unknown fingerprint profile' error, got: %v", err)
	}
}

// --- TestDefaultProfileConstant ---

func TestDefaultProfileConstant(t *testing.T) {
	profile := fingerprints.GetProfile(DefaultProfile)
	if profile == nil {
		t.Errorf("DefaultProfile %s is not a valid profile", DefaultProfile)
	}
}

// --- TestFingerprintHeaderConstant ---

func TestFingerprintHeaderConstant(t *testing.T) {
	if FingerprintHeader != "X-Fingerprint" {
		t.Errorf("FingerprintHeader = %s, want X-Fingerprint", FingerprintHeader)
	}
}

// --- TestNewTransportCache ---

func TestNewTransportCache(t *testing.T) {
	cache := NewTransportCache(time.Minute, 50)

	if cache.ttl != time.Minute {
		t.Errorf("expected TTL to be 1m0s, got %v", cache.ttl)
	}

	if cache.maxEntries != 50 {
		t.Errorf("expected maxEntries to be 50, got %d", cache.maxEntries)
	}

	if cache.transports == nil {
		t.Error("expected transports map to be initialized")
	}
}

// --- TestCacheLength ---

func TestCacheLength(t *testing.T) {
	cache := NewTransportCache(time.Hour, 10)

	if cache.Len() != 0 {
		t.Errorf("expected initial length 0, got %d", cache.Len())
	}

	cache.GetOrCreate("chrome_133")
	if cache.Len() != 1 {
		t.Errorf("expected length 1, got %d", cache.Len())
	}

	cache.GetOrCreate("firefox_147")
	if cache.Len() != 2 {
		t.Errorf("expected length 2, got %d", cache.Len())
	}

	// Same profile should not increase length
	cache.GetOrCreate("chrome_133")
	if cache.Len() != 2 {
		t.Errorf("expected length 2 after duplicate, got %d", cache.Len())
	}
}
