package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fixture is the deterministic mock scorer's ground truth: profile name ->
// continuity score. This is the CI-safe stand-in for a real scoring
// endpoint (see docs/eval-harness-plan.md §3).
var fixture = map[string]float64{
	"chrome_133":  0.91,
	"firefox_147": 0.87,
	"safari_16_0": 0.42,
}

func mockScorerServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profile := r.Header.Get("X-Fingerprint")
		score, ok := fixture[profile]
		if !ok {
			http.Error(w, "unknown profile", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]float64{"continuity_score": score})
	}))
}

func TestRun_MockScorerDeterministicFixture(t *testing.T) {
	srv := mockScorerServer(t)
	defer srv.Close()

	request := func(profile, target string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Fingerprint", profile)
		return http.DefaultClient.Do(req)
	}

	names := []string{"chrome_133", "firefox_147", "safari_16_0", "unknown_profile"}
	results := Run(names, srv.URL, request, JSONScorer)

	if len(results) != len(names) {
		t.Fatalf("want %d results, got %d", len(names), len(results))
	}

	byProfile := make(map[string]Result, len(results))
	for _, r := range results {
		byProfile[r.Profile] = r
	}

	for profile, wantScore := range fixture {
		got, ok := byProfile[profile]
		if !ok {
			t.Fatalf("missing result for profile %s", profile)
		}
		if got.Err != "" {
			t.Errorf("profile %s: unexpected error %q", profile, got.Err)
		}
		if got.Score != wantScore {
			t.Errorf("profile %s: want score %v, got %v", profile, wantScore, got.Score)
		}
	}

	unknown, ok := byProfile["unknown_profile"]
	if !ok {
		t.Fatalf("missing result for unknown_profile")
	}
	if unknown.Err == "" {
		t.Errorf("expected error for unknown_profile, got score %v", unknown.Score)
	}

	// Results must be sorted by profile name for a reproducible table.
	for i := 1; i < len(results); i++ {
		if results[i-1].Profile > results[i].Profile {
			t.Errorf("results not sorted: %s appears before %s", results[i-1].Profile, results[i].Profile)
		}
	}
}

func TestTable(t *testing.T) {
	results := []Result{
		{Profile: "chrome_133", Score: 0.91},
		{Profile: "unknown_profile", Err: "unknown profile"},
	}
	table := Table(results)
	if !strings.Contains(table, "chrome_133") || !strings.Contains(table, "0.9100") {
		t.Errorf("table missing expected score row: %s", table)
	}
	if !strings.Contains(table, "unknown_profile") || !strings.Contains(table, "unknown profile") {
		t.Errorf("table missing expected error row: %s", table)
	}
}

func TestParseProfileListOutput(t *testing.T) {
	sample := "Available fingerprint profiles:\n" +
		"  chrome_133           - chrome_133 (HTTP/3: false, PSK: false)\n" +
		"  firefox_147          - firefox_147 (HTTP/3: true, PSK: false)\n" +
		"\n" +
		"Default profile: chrome_133\n" +
		"\n" +
		"You can also use aliases: chrome, firefox, safari, edge, etc.\n" +
		"\n" +
		"Request headers for routing:\n" +
		"  X-Fingerprint: Specify fingerprint profile (e.g., chrome_133, firefox_147)\n" +
		"  X-FP-Proxy:    Specify upstream proxy (e.g., socks5://user:pass@host:port)\n"

	names := parseProfileListOutput(sample)
	want := []string{"chrome_133", "firefox_147"}
	if len(names) != len(want) {
		t.Fatalf("want %d names, got %d: %v", len(want), len(names), names)
	}
	for i, n := range want {
		if names[i] != n {
			t.Errorf("names[%d] = %q, want %q", i, names[i], n)
		}
	}
}
