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
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
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
		resp.Body.Close()
		if err != nil {
			results = append(results, Result{Profile: p, Err: err.Error()})
			continue
		}
		results = append(results, Result{Profile: p, Score: s})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Profile < results[j].Profile })
	return results
}

// JSONScorer decodes {"continuity_score": <float>} from resp.Body.
func JSONScorer(resp *http.Response) (float64, error) {
	var body struct {
		ContinuityScore float64 `json:"continuity_score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, fmt.Errorf("decode score response: %w", err)
	}
	return body.ContinuityScore, nil
}

// Table renders results as a markdown table.
func Table(results []Result) string {
	var b strings.Builder
	b.WriteString("| Profile | Score | Error |\n|---|---|---|\n")
	for _, r := range results {
		fmt.Fprintf(&b, "| %s | %.4f | %s |\n", r.Profile, r.Score, r.Err)
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

// listProfiles asks the fingerprintproxy binary itself for the canonical
// profile list, so this harness never carries its own copy of profiles.go's
// registry that could drift out of sync with it.
func listProfiles(binPath string) ([]string, error) {
	out, err := exec.Command(binPath, "-list").Output()
	if err != nil {
		return nil, fmt.Errorf("run %s -list: %w", binPath, err)
	}
	names := parseProfileListOutput(string(out))
	if len(names) == 0 {
		return nil, fmt.Errorf("%s -list produced no profile names", binPath)
	}
	return names, nil
}

func main() {
	proxyAddr := flag.String("proxy", "localhost:8080", "fingerprintproxy HTTP proxy address (must already be running)")
	fppBin := flag.String("fpp-bin", "fingerprintproxy", "path to the fingerprintproxy binary, used to list profiles via -list")
	target := flag.String("target", os.Getenv("EVAL_TARGET_URL"), "continuity-scoring endpoint URL (env EVAL_TARGET_URL)")
	real := flag.Bool("real", os.Getenv("EVAL_REAL") == "1", "actually hit -target (opt-in; env EVAL_REAL=1). Without it this only prints the plan and exits.")
	flag.Parse()

	names, err := listProfiles(*fppBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if !*real {
		fmt.Printf("Dry run: would score %d profiles against %q via proxy %q.\n", len(names), *target, *proxyAddr)
		fmt.Println("Set -real (or EVAL_REAL=1) and -target (or EVAL_TARGET_URL) to run for real.")
		return
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "error: -target (or EVAL_TARGET_URL) is required for a real run")
		os.Exit(1)
	}

	proxyURL, err := url.Parse("http://" + *proxyAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid -proxy address: %v\n", err)
		os.Exit(1)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	request := func(profile, target string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Fingerprint", profile)
		return client.Do(req)
	}

	results := Run(names, *target, request, JSONScorer)
	fmt.Print(Table(results))
}
