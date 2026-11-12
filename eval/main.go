// Command eval is the adversarial eval harness: it drives fingerprintproxy
// across its full profile set against a configurable continuity-scoring
// endpoint and prints a reproducible per-profile score table.
//
// It never contacts a real target unless explicitly opted in via -real (or
// EVAL_REAL=1) and -target/EVAL_TARGET_URL; with no flags it only prints
// what it would do and exits 0.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	// defaultFppBin is the -fpp-bin flag's default value. When it's left
	// unchanged and no such binary is installed, listProfiles falls back to
	// building it from source so a dry run works from a clean checkout.
	defaultFppBin = "fingerprintproxy"

	// rootPkg is the import path of the fingerprintproxy main package. The
	// source fallback runs it by import path rather than "." so it resolves
	// the same package from any directory inside the module (including
	// eval/ itself, where "." would be this harness).
	rootPkg = "github.com/tomkabel/fingerprintproxy"

	// maxScoreBody caps how much of a scorer response is read; a continuity
	// score is a few bytes, so anything larger is a misbehaving endpoint.
	maxScoreBody = 1 << 20

	// maxErrDetail caps the subprocess stderr echoed into an error message.
	maxErrDetail = 500
)

// Requester performs one HTTP round trip through a running fingerprintproxy
// instance, using profile as the X-Fingerprint header value, against target.
type Requester func(profile, target string) (*http.Response, error)

// Scorer extracts a continuity score from the target's response body. The
// caller closes resp.Body.
type Scorer func(resp *http.Response) (float64, error)

// Result is one profile's outcome against the target scorer.
type Result struct {
	Profile string
	Score   float64
	Err     string // set instead of Score on request/decode failure
}

// Run drives every profile in names against target, recording the score (or
// error) the scorer derives from each response. Results are sorted by
// profile name so the output table is reproducible run to run.
func Run(names []string, target string, request Requester, score Scorer) []Result {
	results := make([]Result, 0, len(names))
	for _, p := range names {
		resp, err := request(p, target)
		if err != nil {
			results = append(results, Result{Profile: p, Err: err.Error()})
			continue
		}
		s, err := score(resp)
		_ = resp.Body.Close()
		if err != nil {
			results = append(results, Result{Profile: p, Err: err.Error()})
			continue
		}
		results = append(results, Result{Profile: p, Score: s})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Profile < results[j].Profile })
	return results
}

// JSONScorer decodes {"continuity_score": <float>} from resp.Body. A non-2xx
// status is an error, as is a body without continuity_score: the field is a
// pointer so an omitted field is reported rather than silently scored as 0
// (encoding/json leaves missing fields at their zero value, which is
// indistinguishable from a genuine zero score). The body read is capped at
// maxScoreBody.
func JSONScorer(resp *http.Response) (float64, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return 0, fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	var body struct {
		ContinuityScore *float64 `json:"continuity_score"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxScoreBody)).Decode(&body); err != nil {
		return 0, fmt.Errorf("decode score response: %w", err)
	}
	if body.ContinuityScore == nil {
		return 0, errors.New("decode score response: missing continuity_score")
	}
	return *body.ContinuityScore, nil
}

// normalizeProxyAddr prepends the default http:// scheme to addr if it
// doesn't already have one (e.g. "localhost:8080" -> "http://localhost:8080"),
// leaving an already-schemed address (e.g. "socks5://host:1080") untouched.
func normalizeProxyAddr(addr string) string {
	if strings.Contains(addr, "://") {
		return addr
	}
	return "http://" + addr
}

// parseURL parses raw and requires one of schemes and a non-empty host, so a
// typo like "htp://x" or "http://" fails up front instead of mid-run.
func parseURL(raw string, schemes ...string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	for _, s := range schemes {
		if u.Scheme == s && u.Host != "" {
			return u, nil
		}
	}
	return nil, fmt.Errorf("%q must be a %s URL with a host", raw, strings.Join(schemes, "/"))
}

// cellEscaper keeps arbitrary error text from breaking the markdown table.
var cellEscaper = strings.NewReplacer("|", `\|`, "\r\n", " ", "\n", " ", "\r", " ")

// Table renders results as a markdown table.
func Table(results []Result) string {
	var b strings.Builder
	b.WriteString("| Profile | Score | Error |\n|---|---|---|\n")
	for _, r := range results {
		fmt.Fprintf(&b, "| %s | %.4f | %s |\n", cellEscaper.Replace(r.Profile), r.Score, cellEscaper.Replace(r.Err))
	}
	return b.String()
}

// parseProfileListOutput extracts profile names from `fingerprintproxy
// -list` output (lines of the form "  <name>           - ...").
func parseProfileListOutput(output string) []string {
	var names []string
	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		line := sc.Text()
		// Profile lines look like "  <name>   - <name> (HTTP/3: ..., PSK: ...)".
		// Other indented lines in the output (e.g. the trailing header-usage
		// notes) also start with two spaces but don't contain " - ", so
		// require that too.
		if !strings.HasPrefix(line, "  ") || !strings.Contains(line, " - ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		names = append(names, fields[0])
	}
	return names
}

// profileListCommand returns the command that prints the canonical profile
// list. With the default binPath and no installed binary it runs the root
// package from source instead of failing outright. GOPROXY=off keeps that
// fallback honoring the package's network-free-by-default contract: with a
// warm module cache (the common case, since building/testing this repo
// already populates it) it is a no-op, but on a cold cache it fails fast with
// a clear error instead of silently reaching out to the network.
func profileListCommand(binPath string) *exec.Cmd {
	if binPath == defaultFppBin {
		if _, err := exec.LookPath(binPath); err != nil {
			cmd := exec.Command("go", "run", rootPkg, "-list")
			cmd.Env = append(os.Environ(), "GOPROXY=off")
			return cmd
		}
	}
	return exec.Command(binPath, "-list")
}

// listProfiles asks the fingerprintproxy binary itself for the canonical
// profile list, so this harness never carries its own copy of profiles.go's
// registry that could drift out of sync with it.
func listProfiles(binPath string) ([]string, error) {
	cmd := profileListCommand(binPath)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			if detail := strings.TrimSpace(string(exitErr.Stderr)); detail != "" {
				if len(detail) > maxErrDetail {
					detail = detail[:maxErrDetail] + "..."
				}
				return nil, fmt.Errorf("run %s: %w: %s", strings.Join(cmd.Args, " "), err, detail)
			}
		}
		return nil, fmt.Errorf("run %s: %w", strings.Join(cmd.Args, " "), err)
	}
	names := parseProfileListOutput(string(out))
	if len(names) == 0 {
		return nil, fmt.Errorf("%s produced no profile names", strings.Join(cmd.Args, " "))
	}
	return names, nil
}

// newRequester returns a Requester that sends a GET to the target using
// client (which should already be configured to route through the proxy) with
// the profile in the X-Fingerprint header.
func newRequester(client *http.Client) Requester {
	return func(profile, target string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Fingerprint", profile)
		return client.Do(req)
	}
}

// main runs the harness with the process environment and exits with its
// status.
func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// run is main's testable body: it parses args, reads defaults through getenv,
// writes to stdout/stderr and returns the process exit code (0 ok, 1 runtime
// error, 2 usage error).
func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(stderr)
	proxyAddr := fs.String("proxy", "localhost:8080", "fingerprintproxy HTTP proxy address (must already be running); a URL scheme is optional and defaults to http://")
	fppBin := fs.String("fpp-bin", defaultFppBin, "path to the fingerprintproxy binary, used to list profiles via -list (falls back to `go run` of the root package if left at the default and not found on PATH)")
	target := fs.String("target", getenv("EVAL_TARGET_URL"), "continuity-scoring endpoint URL (env EVAL_TARGET_URL)")
	real := fs.Bool("real", getenv("EVAL_REAL") == "1", "actually hit -target (opt-in; env EVAL_REAL=1). Without it this only prints the plan and exits.")
	timeout := fs.Duration("timeout", 30*time.Second, "per-request HTTP timeout for real runs")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	names, err := listProfiles(*fppBin)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	if !*real {
		fmt.Fprintf(stdout, "Dry run: would score %d profiles against %q via proxy %q.\n", len(names), *target, *proxyAddr)
		fmt.Fprintln(stdout, "Set -real (or EVAL_REAL=1) and -target (or EVAL_TARGET_URL) to run for real.")
		return 0
	}
	if *target == "" {
		fmt.Fprintln(stderr, "error: -target (or EVAL_TARGET_URL) is required for a real run")
		return 1
	}
	targetURL, err := parseURL(*target, "http", "https")
	if err != nil {
		fmt.Fprintf(stderr, "error: invalid -target: %v\n", err)
		return 1
	}
	proxyURL, err := parseURL(normalizeProxyAddr(*proxyAddr), "http", "https", "socks5", "socks5h")
	if err != nil {
		fmt.Fprintf(stderr, "error: invalid -proxy address: %v\n", err)
		return 1
	}

	client := &http.Client{
		Timeout:   *timeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	results := Run(names, targetURL.String(), newRequester(client), JSONScorer)
	fmt.Fprint(stdout, Table(results))
	return 0
}
