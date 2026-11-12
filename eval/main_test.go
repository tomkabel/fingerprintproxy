package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// fakeFppEnv selects the behavior of the test binary when it is re-executed
// as a stand-in for the fingerprintproxy binary (see TestMain).
const fakeFppEnv = "EVAL_TEST_FAKE_FPP"

// fakeListOutput mimics the real `fingerprintproxy -list` output for the
// fixture profiles, including the non-profile lines the parser must skip.
const fakeListOutput = "Available fingerprint profiles:\n" +
	"  chrome_133           - chrome_133 (HTTP/3: false, PSK: false)\n" +
	"  firefox_147          - firefox_147 (HTTP/3: true, PSK: false)\n" +
	"  safari_16_0          - safari_16_0 (HTTP/3: false, PSK: false)\n" +
	"\n" +
	"Default profile: chrome_133\n" +
	"\n" +
	"Request headers for routing:\n" +
	"  X-Fingerprint: Specify fingerprint profile (e.g., chrome_133, firefox_147)\n"

// TestMain lets the test binary double as a fake fingerprintproxy: when
// fakeFppEnv is set it prints a canned `-list` response (or fails) instead
// of running tests, so listProfiles/run are exercised end to end without
// building or installing the real binary.
func TestMain(m *testing.M) {
	switch os.Getenv(fakeFppEnv) {
	case "list":
		fmt.Print(fakeListOutput)
		os.Exit(0)
	case "empty":
		fmt.Print("Available fingerprint profiles:\n")
		os.Exit(0)
	case "fail":
		fmt.Fprintln(os.Stderr, "boom: cannot build profiles")
		os.Exit(3)
	}
	os.Exit(m.Run())
}

// useFakeFpp points the re-exec'd test binary at the given fake mode and
// returns its path for use as -fpp-bin.
func useFakeFpp(t *testing.T, mode string) string {
	t.Helper()
	t.Setenv(fakeFppEnv, mode)
	return os.Args[0]
}

// mockScorerServer serves fixture scores keyed by the X-Fingerprint header
// and 400s for unknown profiles.
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

// getBody issues a GET against url and returns the response; the caller
// closes the body.
func getBody(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

// TestRun_MockScorerDeterministicFixture verifies Run scores each profile
// from the mock endpoint, records an error for an unknown profile, and
// returns results sorted by profile name.
func TestRun_MockScorerDeterministicFixture(t *testing.T) {
	srv := mockScorerServer(t)
	defer srv.Close()

	names := []string{"chrome_133", "firefox_147", "safari_16_0", "unknown_profile"}
	results := Run(names, srv.URL, newRequester(http.DefaultClient), JSONScorer)

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

// TestRun_RequestError verifies a failed round trip is recorded as that
// profile's error without aborting the remaining profiles.
func TestRun_RequestError(t *testing.T) {
	request := func(string, string) (*http.Response, error) { return nil, errors.New("connection refused") }
	results := Run([]string{"a", "b"}, "ignored", request, JSONScorer)
	if len(results) != 2 || results[0].Err != "connection refused" || results[1].Err != "connection refused" {
		t.Fatalf("want both profiles recorded as connection-refused, got %+v", results)
	}
}

// TestJSONScorer verifies the scorer accepts a valid score (including a
// genuine zero) and rejects non-2xx statuses, missing fields, malformed JSON
// and bodies over the size cap.
func TestJSONScorer(t *testing.T) {
	big := `{"continuity_score": 1, "pad": "` + strings.Repeat("a", maxScoreBody) + `"}`
	cases := []struct {
		name    string
		status  int
		body    string
		want    float64
		wantErr string
	}{
		{name: "valid", status: 200, body: `{"continuity_score": 0.5}`, want: 0.5},
		{name: "genuine zero", status: 200, body: `{"continuity_score": 0}`, want: 0},
		{name: "missing field", status: 200, body: `{}`, wantErr: "missing continuity_score"},
		{name: "malformed", status: 200, body: `<html>`, wantErr: "decode score response"},
		{name: "bad status", status: 403, body: `{"continuity_score": 1}`, wantErr: "unexpected HTTP status 403"},
		{name: "over size cap", status: 200, body: big, wantErr: "decode score response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			resp := getBody(t, srv.URL)
			defer func() { _ = resp.Body.Close() }()

			got, err := JSONScorer(resp)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got score %v err %v", tc.wantErr, got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("want %v, got %v err %v", tc.want, got, err)
			}
		})
	}
}

// TestNormalizeProxyAddr verifies a bare host:port gets http:// while an
// already-schemed address is left alone.
func TestNormalizeProxyAddr(t *testing.T) {
	cases := map[string]string{
		"localhost:8080":            "http://localhost:8080",
		"http://localhost:8080":     "http://localhost:8080",
		"socks5://localhost:1080":   "socks5://localhost:1080",
		"https://proxy.example:443": "https://proxy.example:443",
	}
	for in, want := range cases {
		if got := normalizeProxyAddr(in); got != want {
			t.Errorf("normalizeProxyAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParseURL verifies scheme and host validation.
func TestParseURL(t *testing.T) {
	for _, ok := range []string{"http://a.example/x", "https://a.example:8443"} {
		if _, err := parseURL(ok, "http", "https"); err != nil {
			t.Errorf("parseURL(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"ftp://a.example", "http://", "a.example", "://x", "file:///etc/passwd"} {
		if _, err := parseURL(bad, "http", "https"); err == nil {
			t.Errorf("parseURL(%q) = nil error, want rejection", bad)
		}
	}
}

// TestTable verifies score and error rows render, and that error text with
// pipes or newlines cannot break the markdown table.
func TestTable(t *testing.T) {
	results := []Result{
		{Profile: "chrome_133", Score: 0.91},
		{Profile: "unknown_profile", Err: "unknown profile"},
		{Profile: "weird", Err: "a|b\nc"},
	}
	table := Table(results)
	if !strings.Contains(table, "chrome_133") || !strings.Contains(table, "0.9100") {
		t.Errorf("table missing expected score row: %s", table)
	}
	if !strings.Contains(table, "unknown_profile") || !strings.Contains(table, "unknown profile") {
		t.Errorf("table missing expected error row: %s", table)
	}
	if !strings.Contains(table, `| a\|b c |`) {
		t.Errorf("error text not escaped: %s", table)
	}
	if got, want := strings.Count(table, "\n"), 2+len(results); got != want {
		t.Errorf("table has %d lines, want %d (an error cell leaked a newline)", got, want)
	}
}

// TestParseProfileListOutput verifies only profile lines are extracted from
// `-list` output, skipping the indented header-usage notes.
func TestParseProfileListOutput(t *testing.T) {
	names := parseProfileListOutput(fakeListOutput)
	want := []string{"chrome_133", "firefox_147", "safari_16_0"}
	if len(names) != len(want) {
		t.Fatalf("want %d names, got %d: %v", len(want), len(names), names)
	}
	for i, n := range want {
		if names[i] != n {
			t.Errorf("names[%d] = %q, want %q", i, names[i], n)
		}
	}
}

// TestProfileListCommand verifies the source fallback is used only for the
// default -fpp-bin when it isn't on PATH, that it targets the root package by
// import path (so it works from eval/ too) and that it disables the network.
func TestProfileListCommand(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // nothing installed

	cmd := profileListCommand(defaultFppBin)
	if got, want := strings.Join(cmd.Args, " "), "go run "+rootPkg+" -list"; got != want {
		t.Errorf("fallback command = %q, want %q", got, want)
	}
	var goproxyOff bool
	for _, kv := range cmd.Env {
		goproxyOff = goproxyOff || kv == "GOPROXY=off"
	}
	if !goproxyOff {
		t.Error("fallback must set GOPROXY=off")
	}

	if got := profileListCommand("/custom/bin"); got.Args[0] != "/custom/bin" || got.Env != nil {
		t.Errorf("explicit -fpp-bin must run as-is, got %v env=%v", got.Args, got.Env)
	}

	installed := filepath.Join(t.TempDir(), defaultFppBin)
	if err := os.WriteFile(installed, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(installed))
	if got := profileListCommand(defaultFppBin); got.Env != nil {
		t.Errorf("installed binary must not use the source fallback, got %v", got.Args)
	}
}

// TestRootPkgMatchesModule guards rootPkg against drifting from go.mod.
func TestRootPkgMatchesModule(t *testing.T) {
	mod, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(mod), "module "+rootPkg+"\n") {
		t.Errorf("go.mod does not start with %q; update rootPkg", "module "+rootPkg)
	}
}

// TestListProfiles verifies listProfiles returns the names from a working
// binary and surfaces stderr for a failing or empty one.
func TestListProfiles(t *testing.T) {
	names, err := listProfiles(useFakeFpp(t, "list"))
	if err != nil || len(names) != 3 {
		t.Fatalf("want 3 names, got %v err %v", names, err)
	}

	if _, err := listProfiles(useFakeFpp(t, "fail")); err == nil || !strings.Contains(err.Error(), "boom: cannot build profiles") {
		t.Errorf("want stderr in error, got %v", err)
	}

	if _, err := listProfiles(useFakeFpp(t, "empty")); err == nil || !strings.Contains(err.Error(), "produced no profile names") {
		t.Errorf("want empty-list error, got %v", err)
	}

	if _, err := listProfiles(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("want error for a nonexistent binary")
	}
}

// runCLI invokes run with the given args and env map and returns the exit
// code with captured stdout and stderr.
func runCLI(args []string, env map[string]string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, func(k string) string { return env[k] }, &out, &errOut)
	return code, out.String(), errOut.String()
}

// TestRun_CLI covers the command's flag handling and dry-run/real-run paths
// end to end against a fake binary and a fake HTTP proxy.
func TestRun_CLI(t *testing.T) {
	bin := useFakeFpp(t, "list")

	t.Run("dry run by default", func(t *testing.T) {
		code, out, _ := runCLI([]string{"-fpp-bin", bin}, nil)
		if code != 0 || !strings.Contains(out, "Dry run: would score 3 profiles") {
			t.Fatalf("code=%d out=%q", code, out)
		}
	})

	t.Run("help exits zero", func(t *testing.T) {
		if code, _, errOut := runCLI([]string{"-h"}, nil); code != 0 || !strings.Contains(errOut, "-target") {
			t.Fatalf("code=%d stderr=%q", code, errOut)
		}
	})

	t.Run("bad flag is a usage error", func(t *testing.T) {
		if code, _, _ := runCLI([]string{"-nope"}, nil); code != 2 {
			t.Fatalf("code=%d, want 2", code)
		}
	})

	t.Run("profile listing failure", func(t *testing.T) {
		failBin := useFakeFpp(t, "fail")
		code, _, errOut := runCLI([]string{"-fpp-bin", failBin}, nil)
		if code != 1 || !strings.Contains(errOut, "error:") {
			t.Fatalf("code=%d stderr=%q", code, errOut)
		}
		useFakeFpp(t, "list")
	})

	t.Run("real run needs a target", func(t *testing.T) {
		code, _, errOut := runCLI([]string{"-fpp-bin", bin, "-real"}, nil)
		if code != 1 || !strings.Contains(errOut, "-target") {
			t.Fatalf("code=%d stderr=%q", code, errOut)
		}
	})

	t.Run("rejects invalid target and proxy", func(t *testing.T) {
		for _, args := range [][]string{
			{"-fpp-bin", bin, "-real", "-target", "ftp://x.example"},
			{"-fpp-bin", bin, "-real", "-target", "http://x.example", "-proxy", "ftp://p.example"},
		} {
			if code, _, errOut := runCLI(args, nil); code != 1 || !strings.Contains(errOut, "invalid") {
				t.Errorf("args=%v code=%d stderr=%q", args, code, errOut)
			}
		}
	})

	t.Run("real run through a proxy", func(t *testing.T) {
		// A plain-HTTP request through an HTTP proxy arrives at the proxy
		// with an absolute URI, so one handler plays proxy and scorer.
		proxy := mockScorerServer(t)
		defer proxy.Close()

		env := map[string]string{"EVAL_REAL": "1", "EVAL_TARGET_URL": "http://scorer.invalid/score"}
		code, out, errOut := runCLI([]string{"-fpp-bin", bin, "-proxy", proxy.Listener.Addr().String(), "-timeout", "10s"}, env)
		if code != 0 || errOut != "" {
			t.Fatalf("code=%d stderr=%q", code, errOut)
		}
		for profile, score := range fixture {
			if want := fmt.Sprintf("| %s | %.4f |  |", profile, score); !strings.Contains(out, want) {
				t.Errorf("table missing %q:\n%s", want, out)
			}
		}
	})
}
