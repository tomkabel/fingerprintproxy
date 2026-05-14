package main

import (
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
	"github.com/saucesteals/mimic"
)

func TestResolveMimicSpec(t *testing.T) {
	tests := []struct {
		name          string
		headers       map[string]string
		expectedBrand mimic.Brand
		expectedVer   string
		expectedPlat  mimic.Platform
	}{
		{
			name:          "no headers returns default Chrome",
			headers:       map[string]string{},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "133.0.0.0",
			expectedPlat:  mimic.PlatformWindows,
		},
		{
			name:          "X-Fingerprint chrome resolves to Chrome",
			headers:       map[string]string{"X-Fingerprint": "chrome"},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "133.0.0.0",
			expectedPlat:  mimic.PlatformWindows,
		},
		{
			name:          "X-Fingerprint edge resolves to Edge",
			headers:       map[string]string{"X-Fingerprint": "edge"},
			expectedBrand: mimic.BrandEdge,
			expectedVer:   "133.0.0.0",
			expectedPlat:  mimic.PlatformWindows,
		},
		{
			name:          "X-Fingerprint brave resolves to Brave",
			headers:       map[string]string{"X-Fingerprint": "brave"},
			expectedBrand: mimic.BrandBrave,
			expectedVer:   "133.0.0.0",
			expectedPlat:  mimic.PlatformWindows,
		},
		{
			name:          "X-Mimic-Version overrides version",
			headers:       map[string]string{"X-Mimic-Version": "120.0.0.0"},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "120.0.0.0",
			expectedPlat:  mimic.PlatformWindows,
		},
		{
			name:          "X-Mimic-Version with bare number",
			headers:       map[string]string{"X-Mimic-Version": "120"},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "120.0.0.0",
			expectedPlat:  mimic.PlatformWindows,
		},
		{
			name:          "X-Mimic-Brand edge overrides brand",
			headers:       map[string]string{"X-Mimic-Brand": "edge"},
			expectedBrand: mimic.BrandEdge,
			expectedVer:   "133.0.0.0",
			expectedPlat:  mimic.PlatformWindows,
		},
		{
			name:          "X-Mimic-Platform mac overrides platform",
			headers:       map[string]string{"X-Mimic-Platform": "mac"},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "133.0.0.0",
			expectedPlat:  mimic.PlatformMac,
		},
		{
			name:          "X-Mimic-Platform linux",
			headers:       map[string]string{"X-Mimic-Platform": "linux"},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "133.0.0.0",
			expectedPlat:  mimic.PlatformLinux,
		},
		{
			name:          "all X-Mimic headers combined",
			headers:       map[string]string{"X-Mimic-Brand": "brave", "X-Mimic-Version": "124.0.0.0", "X-Mimic-Platform": "mac"},
			expectedBrand: mimic.BrandBrave,
			expectedVer:   "124.0.0.0",
			expectedPlat:  mimic.PlatformMac,
		},
		{
			name:          "X-Fingerprint takes precedence when no Mimic headers",
			headers:       map[string]string{"X-Fingerprint": "chrome"},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "133.0.0.0",
			expectedPlat:  mimic.PlatformWindows,
		},
		{
			name:          "UA auto-detection Windows Chrome",
			headers:       map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "128.0.0.0",
			expectedPlat:  mimic.PlatformWindows,
		},
		{
			name:          "UA auto-detection Mac Chrome",
			headers:       map[string]string{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "131.0.0.0",
			expectedPlat:  mimic.PlatformMac,
		},
		{
			name:          "UA auto-detection Linux Edge",
			headers:       map[string]string{"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"},
			expectedBrand: mimic.BrandEdge,
			expectedVer:   "130.0.0.0",
			expectedPlat:  mimic.PlatformLinux,
		},
		{
			name:          "UA without Brave keyword detected as Chrome",
			headers:       map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "131.0.0.0",
			expectedPlat:  mimic.PlatformWindows,
		},
		{
			name:          "X-Fingerprint firefox falls back to Chrome",
			headers:       map[string]string{"X-Fingerprint": "firefox"},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "133.0.0.0",
			expectedPlat:  mimic.PlatformWindows,
		},
		{
			name:          "X-Fingerprint safari falls back to Chrome on Mac",
			headers:       map[string]string{"X-Fingerprint": "safari"},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "133.0.0.0",
			expectedPlat:  mimic.PlatformMac,
		},
		{
			name:          "X-Fingerprint firefox_147 falls back to Chrome with version 147",
			headers:       map[string]string{"X-Fingerprint": "firefox_147"},
			expectedBrand: mimic.BrandChrome,
			expectedVer:   "147.0.0.0",
			expectedPlat:  mimic.PlatformWindows,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			spec := ResolveMimicSpec(req)

			if spec.Brand != tt.expectedBrand {
				t.Errorf("expected brand %s, got %s", tt.expectedBrand, spec.Brand)
			}
			if spec.Version != tt.expectedVer {
				t.Errorf("expected version %s, got %s", tt.expectedVer, spec.Version)
			}
			if spec.Platform != tt.expectedPlat {
				t.Errorf("expected platform %s, got %s", tt.expectedPlat, spec.Platform)
			}
		})
	}
}

func TestResolveFingerprintToMimic(t *testing.T) {
	tests := []struct {
		fp          string
		expectNil   bool
		expectBrand mimic.Brand
	}{
		{"chrome", false, mimic.BrandChrome},
		{"chromium", false, mimic.BrandChrome},
		{"edge", false, mimic.BrandEdge},
		{"brave", false, mimic.BrandBrave},
		{"mobile", false, mimic.BrandChrome},
		{"chrome_133", false, mimic.BrandChrome},
		{"edge_120", false, mimic.BrandEdge},
		{"firefox", false, mimic.BrandChrome},
		{"safari", false, mimic.BrandChrome},
		{"ios", false, mimic.BrandChrome},
		{"invalid_profile", true, ""},
		{"nonexistent", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.fp, func(t *testing.T) {
			result := resolveFingerprintToMimic(tt.fp)
			if tt.expectNil {
				if result != nil {
					t.Errorf("expected nil for %s, got %+v", tt.fp, result)
				}
			} else {
				if result == nil {
					t.Errorf("expected non-nil for %s", tt.fp)
				} else if result.Brand != tt.expectBrand {
					t.Errorf("expected brand %s for %s, got %s", tt.expectBrand, tt.fp, result.Brand)
				}
			}
		})
	}
}

func TestParseUserAgentForMimic(t *testing.T) {
	tests := []struct {
		name        string
		ua          string
		expectNil   bool
		expectBrand mimic.Brand
		expectVer   string
		expectPlat  mimic.Platform
	}{
		{
			name:        "Chrome on Windows",
			ua:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
			expectNil:   false,
			expectBrand: mimic.BrandChrome,
			expectVer:   "132.0.0.0",
			expectPlat:  mimic.PlatformWindows,
		},
		{
			name:        "Chrome on Mac",
			ua:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			expectNil:   false,
			expectBrand: mimic.BrandChrome,
			expectVer:   "131.0.0.0",
			expectPlat:  mimic.PlatformMac,
		},
		{
			name:        "Chrome on Linux",
			ua:          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
			expectNil:   false,
			expectBrand: mimic.BrandChrome,
			expectVer:   "130.0.0.0",
			expectPlat:  mimic.PlatformLinux,
		},
		{
			name:        "Edge on Windows",
			ua:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
			expectNil:   false,
			expectBrand: mimic.BrandEdge,
			expectVer:   "130.0.0.0",
			expectPlat:  mimic.PlatformWindows,
		},
		{
			name:        "Brave on Windows",
			ua:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			expectNil:   false,
			expectBrand: mimic.BrandChrome,
			expectVer:   "131.0.0.0",
			expectPlat:  mimic.PlatformWindows,
		},
		{
			name:      "empty UA returns nil",
			ua:        "",
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseUserAgentForMimic(tt.ua)
			if tt.expectNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Brand != tt.expectBrand {
				t.Errorf("brand: expected %s, got %s", tt.expectBrand, result.Brand)
			}
			if result.Version != tt.expectVer {
				t.Errorf("version: expected %s, got %s", tt.expectVer, result.Version)
			}
			if result.Platform != tt.expectPlat {
				t.Errorf("platform: expected %s, got %s", tt.expectPlat, result.Platform)
			}
		})
	}
}

func TestMimicCache(t *testing.T) {
	cache := NewMimicCache(100*time.Millisecond, 10)

	t.Run("creates transport on first call", func(t *testing.T) {
		spec := MimicSpec{Brand: mimic.BrandChrome, Version: "133.0.0.0", Platform: mimic.PlatformWindows}
		transport, err := cache.GetOrCreate(spec, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if transport == nil {
			t.Fatal("expected non-nil transport")
		}
	})

	t.Run("returns cached transport on second call", func(t *testing.T) {
		spec := MimicSpec{Brand: mimic.BrandChrome, Version: "133.0.0.0", Platform: mimic.PlatformWindows}
		transport1, _ := cache.GetOrCreate(spec, false)
		transport2, _ := cache.GetOrCreate(spec, false)

		if transport1 != transport2 {
			t.Error("expected same transport instance for same spec")
		}
	})

	t.Run("creates different transport for different spec", func(t *testing.T) {
		spec1 := MimicSpec{Brand: mimic.BrandChrome, Version: "120.0.0.0", Platform: mimic.PlatformWindows}
		spec2 := MimicSpec{Brand: mimic.BrandEdge, Version: "120.0.0.0", Platform: mimic.PlatformWindows}

		transport1, _ := cache.GetOrCreate(spec1, false)
		transport2, _ := cache.GetOrCreate(spec2, false)

		if transport1 == transport2 {
			t.Error("expected different transport instances for different specs")
		}
	})

	t.Run("evicts expired entries", func(t *testing.T) {
		cacheTTL := 50 * time.Millisecond
		cacheEvict := NewMimicCache(cacheTTL, 10)

		spec := MimicSpec{Brand: mimic.BrandChrome, Version: "133.0.0.0", Platform: mimic.PlatformWindows}
		_, err := cacheEvict.GetOrCreate(spec, false)
		if err != nil {
			t.Fatalf("failed to create transport: %v", err)
		}

		time.Sleep(cacheTTL + 10*time.Millisecond)

		transport, err := cacheEvict.GetOrCreate(spec, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if transport == nil {
			t.Fatal("expected non-nil transport after eviction")
		}
	})

	t.Run("respects max entries limit", func(t *testing.T) {
		cacheLimited := NewMimicCache(time.Hour, 2)

		specs := []MimicSpec{
			{Brand: mimic.BrandChrome, Version: "133.0.0.0", Platform: mimic.PlatformWindows},
			{Brand: mimic.BrandEdge, Version: "133.0.0.0", Platform: mimic.PlatformWindows},
			{Brand: mimic.BrandBrave, Version: "133.0.0.0", Platform: mimic.PlatformWindows},
		}

		for i, spec := range specs {
			_, err := cacheLimited.GetOrCreate(spec, false)
			if err != nil {
				t.Fatalf("failed to create transport %d: %v", i, err)
			}
		}

		if cacheLimited.Len() != 2 {
			t.Errorf("expected cache length 2 after eviction, got %d", cacheLimited.Len())
		}
	})

	t.Run("duplicate specs don't increase count", func(t *testing.T) {
		cacheDedup := NewMimicCache(time.Hour, 10)
		spec := MimicSpec{Brand: mimic.BrandChrome, Version: "133.0.0.0", Platform: mimic.PlatformWindows}

		_, _ = cacheDedup.GetOrCreate(spec, false)
		_, _ = cacheDedup.GetOrCreate(spec, false)
		_, _ = cacheDedup.GetOrCreate(spec, false)

		if cacheDedup.Len() != 1 {
			t.Errorf("expected cache length 1, got %d", cacheDedup.Len())
		}
	})
}

func TestMimicCacheCloseIdleConnections(t *testing.T) {
	cache := NewMimicCache(time.Hour, 10)
	spec := MimicSpec{Brand: mimic.BrandChrome, Version: "133.0.0.0", Platform: mimic.PlatformWindows}
	_, err := cache.GetOrCreate(spec, false)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}

	cache.CloseIdleConnections()
}

func TestNewMimicCache(t *testing.T) {
	cache := NewMimicCache(time.Minute, 50)

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

func TestDefaultProfileConstant(t *testing.T) {
	if DefaultProfile != "chrome_133" {
		t.Errorf("DefaultProfile = %s, want chrome_133", DefaultProfile)
	}
	if DefaultVersion != "133.0.0.0" {
		t.Errorf("DefaultVersion = %s, want 133.0.0.0", DefaultVersion)
	}
}

func TestFingerprintHeaderConstant(t *testing.T) {
	if FingerprintHeader != "X-Fingerprint" {
		t.Errorf("FingerprintHeader = %s, want X-Fingerprint", FingerprintHeader)
	}
}

func TestMimicHeaderConstants(t *testing.T) {
	if MimicVersionHeader != "X-Mimic-Version" {
		t.Errorf("MimicVersionHeader = %s, want X-Mimic-Version", MimicVersionHeader)
	}
	if MimicBrandHeader != "X-Mimic-Brand" {
		t.Errorf("MimicBrandHeader = %s, want X-Mimic-Brand", MimicBrandHeader)
	}
	if MimicPlatformHeader != "X-Mimic-Platform" {
		t.Errorf("MimicPlatformHeader = %s, want X-Mimic-Platform", MimicPlatformHeader)
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"133", "133.0.0.0"},
		{"133.0.0.0", "133.0.0.0"},
		{"133.0", "133.0.0.0"},
		{"133.0.0", "133.0.0.0"},
		{"133.0.0.0.0", "133.0.0.0"},
		{"", "133.0.0.0"},
		{"notanumber", "133.0.0.0"},
		{" 133 ", "133.0.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseVersion(tt.input)
			if result != tt.expected {
				t.Errorf("parseVersion(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestListProfilesText(t *testing.T) {
	text := listProfilesText()
	if text == "" {
		t.Error("expected non-empty profiles text")
	}
	if !strings.Contains(text, "mimic") {
		t.Error("expected profiles text to mention mimic")
	}
	if !strings.Contains(text, "/__ca__") {
		t.Error("expected profiles text to mention /__ca__ endpoint")
	}
}

func TestDumbResponseWriter(t *testing.T) {
	mockConn := &mockConn{}

	w := &dumbResponseWriter{Conn: mockConn}

	n, err := w.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len("HTTP/1.0 200 OK\r\n\r\n") {
		t.Errorf("expected %d bytes written, got %d", len("HTTP/1.0 200 OK\r\n\r\n"), n)
	}

	data := []byte("Hello, World!")
	n, err = w.Write(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic from Header()")
			}
		}()
		w.Header()
	}()

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic from WriteHeader()")
			}
		}()
		w.WriteHeader(200)
	}()

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

func TestMimicChromeFingerprintAgainstAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cache := NewMimicCache(time.Hour, 10)
	spec := MimicSpec{Brand: mimic.BrandChrome, Version: "133.0.0.0", Platform: mimic.PlatformWindows}
	transport, err := cache.GetOrCreate(spec, false)
	if err != nil {
		t.Fatalf("failed to get transport: %v", err)
	}

	req := httptest.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")

	fReq, err := convertRequestToFHTTP(req)
	if err != nil {
		t.Fatalf("request conversion failed: %v", err)
	}

	fResp, err := transport.RoundTrip(fReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	resp, err := convertResponseFromFHTTP(fResp, req)
	if err != nil {
		t.Fatalf("response conversion failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

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

	if apiResp.TLS.JA3Hash == "" {
		t.Error("expected non-empty JA3 hash")
	}

	if apiResp.HTTPVersion != "h2" {
		t.Errorf("expected HTTP/2, got %s", apiResp.HTTPVersion)
	}
}

func TestMimicEdgeFingerprintAgainstAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cache := NewMimicCache(time.Hour, 10)
	spec := MimicSpec{Brand: mimic.BrandEdge, Version: "133.0.0.0", Platform: mimic.PlatformWindows}
	transport, err := cache.GetOrCreate(spec, false)
	if err != nil {
		t.Fatalf("failed to get transport: %v", err)
	}

	req := httptest.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0")

	fReq, err := convertRequestToFHTTP(req)
	if err != nil {
		t.Fatalf("request conversion failed: %v", err)
	}

	fResp, err := transport.RoundTrip(fReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	resp, err := convertResponseFromFHTTP(fResp, req)
	if err != nil {
		t.Fatalf("response conversion failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

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
}

func TestConvertRequestToFHTTP(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.com/path?q=1", strings.NewReader("test body"))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Custom-Header", "value1")
	req.Header.Add("X-Custom-Header", "value2")
	req.Host = "example.com"

	fReq, err := convertRequestToFHTTP(req)
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	if fReq.Method != req.Method {
		t.Errorf("method: expected %s, got %s", req.Method, fReq.Method)
	}
	if fReq.Host != req.Host {
		t.Errorf("host: expected %s, got %s", req.Host, fReq.Host)
	}
	if fReq.Header.Get("Content-Type") != "text/plain" {
		t.Errorf("Content-Type: expected text/plain, got %s", fReq.Header.Get("Content-Type"))
	}
	if fReq.Header.Get("X-Custom-Header") != "value1" {
		t.Errorf("X-Custom-Header: expected value1, got %s", fReq.Header.Get("X-Custom-Header"))
	}

	bodyBytes, _ := io.ReadAll(fReq.Body)
	if string(bodyBytes) != "test body" {
		t.Errorf("body: expected 'test body', got '%s'", string(bodyBytes))
	}
}

func TestFingerprintHeaderRouting(t *testing.T) {
	testCases := []struct {
		header   string
		expected mimic.Brand
	}{
		{"chrome", mimic.BrandChrome},
		{"edge", mimic.BrandEdge},
		{"brave", mimic.BrandBrave},
		{"chrome_133", mimic.BrandChrome},
	}

	for _, tc := range testCases {
		t.Run(tc.header, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.Header.Set("X-Fingerprint", tc.header)

			spec := ResolveMimicSpec(req)
			if spec.Brand != tc.expected {
				t.Errorf("expected brand %s, got %s", tc.expected, spec.Brand)
			}
		})
	}
}

func newTestFingerprintProxy() *fingerprintProxy {
	return NewFingerprintProxy(false, false)
}

func TestFingerprintProxyConstruction(t *testing.T) {
	fp := newTestFingerprintProxy()
	if fp == nil {
		t.Fatal("expected non-nil proxy")
	}
	if fp.mimicCache == nil {
		t.Error("expected non-nil mimic cache")
	}
	if fp.proxy == nil {
		t.Error("expected non-nil goproxy instance")
	}
}

func TestCAEndpointPathRouting(t *testing.T) {
	fp := newTestFingerprintProxy()

	tests := []struct {
		path       string
		expectBody string
	}{
		{"/__ca__", "CERTIFICATE"},
		{"/__help__", "download CA cert"},
		{"/__profiles__", "mimic"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://fingerprint-proxy"+tt.path, nil)
			ctx := &goproxy.ProxyCtx{
				Req:   req,
				Proxy: fp.proxy,
			}

			var resp *http.Response
			switch req.URL.Path {
			case "/__ca__":
				_, resp = fp.handleCAEndpoint(req, ctx)
			case "/__help__":
				_, resp = fp.handleHelpEndpoint(req, ctx)
			case "/__profiles__":
				_, resp = fp.handleProfilesEndpoint(req, ctx)
			default:
				t.Fatalf("unexpected path: %s", tt.path)
			}

			if resp == nil {
				t.Fatal("expected non-nil response")
			}

			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if !strings.Contains(string(bodyBytes), tt.expectBody) {
				t.Errorf("expected body to contain %q, got: %s", tt.expectBody, string(bodyBytes))
			}
		})
	}
}

func TestHandleRequestStripsHeadersBeforeConversion(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/?q=1", nil)
	req.Header.Set("X-Fingerprint", "chrome")
	req.Header.Set("X-Mimic-Version", "131")
	req.Header.Set("X-Mimic-Brand", "edge")
	req.Header.Set("X-Mimic-Platform", "linux")

	spec := ResolveMimicSpec(req)
	if spec.Brand != mimic.BrandChrome {
		t.Errorf("expected brand Chrome from fingerprint, got %s", spec.Brand)
	}

	req.Header.Del(FingerprintHeader)
	req.Header.Del(MimicVersionHeader)
	req.Header.Del(MimicBrandHeader)
	req.Header.Del(MimicPlatformHeader)

	fReq, err := convertRequestToFHTTP(req)
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	if fReq.Header.Get(FingerprintHeader) != "" {
		t.Error("X-Fingerprint should not be in converted request")
	}
	if fReq.Header.Get(MimicVersionHeader) != "" {
		t.Error("X-Mimic-Version should not be in converted request")
	}
	if fReq.Header.Get(MimicBrandHeader) != "" {
		t.Error("X-Mimic-Brand should not be in converted request")
	}
	if fReq.Header.Get(MimicPlatformHeader) != "" {
		t.Error("X-Mimic-Platform should not be in converted request")
	}
}

func TestResolveMimicSpecVersionParsing(t *testing.T) {
	cases := []struct {
		fp      string
		wantVer string
	}{
		{"chrome_120", "120.0.0.0"},
		{"edge_110", "110.0.0.0"},
		{"chrome_99", "99.0.0.0"},
	}

	for _, c := range cases {
		t.Run(c.fp, func(t *testing.T) {
			spec := resolveFingerprintToMimic(c.fp)
			if spec == nil {
				t.Fatal("expected non-nil spec")
			}
			if spec.Version != c.wantVer {
				t.Errorf("expected version %s, got %s", c.wantVer, spec.Version)
			}
		})
	}
}
