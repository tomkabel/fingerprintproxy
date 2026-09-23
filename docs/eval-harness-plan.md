# Eval Harness Plan (T9a/T9b/T9c + T-reconcile)

> **Status note:** this plan was produced by an autonomous agent run with no
> human review checkpoint available. It is self-reviewed against the repo's
> ground rules (never assert an unverified count or benchmark number; no
> invented figures) rather than externally reviewed before implementation, as
> instructed for this run. Treat it as a working plan, not a signed-off spec.

## 0. Verified facts this plan relies on

- `profiles.go`'s `profileRegistry` map has **72 entries**, counted with:
  `awk '/profileRegistry = map/,/^}/' profiles.go | grep -c '":'`
  Independently cross-checked by building the binary and running `-list`:
  `go build -o /tmp/fpproxy . && /tmp/fpproxy -list | grep -c ' - '` → also 72.
  (`go run . -list` piped through a pager produced garbled/duplicated output
  in one throwaway shell session — a terminal/output-interleaving artifact,
  not a real count; the binary + grep count above is the one this plan
  trusts, and it agrees with the handoff's stated 72.)
- Of those 72, **8** have a `_psk` suffix (PSK variants):
  `awk '/profileRegistry = map/,/^}/' profiles.go | grep '":' | grep -c '_psk"'`
  → 64 non-PSK + 8 PSK = 72.
- `"133"` (as in `chrome_133`) is a profile *name* fragment, not a count. It
  must never be presented as one.
- README currently states two different counts ("65+" at line ~24, "80+" at
  line ~147), both stale relative to the code.

## 1. T-reconcile — fix the profile-count inconsistency

**Files touched:** `README.md`.

**Change:** replace both "65+" and "80+" with **72**, and add the counting
command inline so the number is re-derivable by anyone without trusting this
doc:

```
awk '/profileRegistry = map/,/^}/' profiles.go | grep -c '":'
```

State the base/PSK split (64 base + 8 `_psk` variants = 72) using the same
command family, so a reader can verify both numbers themselves. No commit
touches `profiles.go` itself — this task is a docs-only reconciliation.

**Acceptance criteria:** `grep -n '65+\|80+\|"133"' README.md` (as a count)
returns nothing; the number 72 appears with its derivation command; `go build
./... && go test ./...` unaffected (docs-only change).

## 2. T9a — reframe the README: what is/isn't forgeable

**Files touched:** `README.md` (new section, e.g. "What This Proxy Can and
Cannot Forge").

**Content (from the handoff, ground-truth capability list):**
- **Forges:** the TLS ClientHello / JA3 / JA4 fingerprint, per profile —
  cipher suites, extensions, curve/point-format order, ALPN, etc.
- **Does NOT forge:**
  - TCP SYN kernel fields (TTL, window size, option order) — these come from
    the OS network stack the proxy runs on, not from `tls-client`.
  - H2/H3 frame *timing and behavior* (settings-frame cadence, stream
    prioritization patterns actually observed over time) — `tls-client`
    can set static H2/H3 settings values but does not reproduce a real
    browser's runtime frame-timing behavior.
  - WebSocket cadence — out of scope entirely; this proxy is HTTP(S) only.
  - **Cross-layer coherence** — a spoofed Chrome ClientHello arriving over a
    Linux-container TCP stack, possibly through a residential proxy with its
    own TTL/window signature, is internally inconsistent even though each
    individual layer looks plausible in isolation.

**Framing:** this is presented as the honest, defensible argument for
multi-signal detection — single-layer (TLS-only) spoofing is cheap and
widely available (this repo is an existence proof); coherent multi-layer
spoofing is a materially harder and more expensive problem. No claim is made
about any specific third-party detection product's effectiveness — the repo
states only what *this proxy* does and does not do.

**Acceptance criteria:** section exists, uses only the verified capability
list above (no new unverified claims about detection products), plain
present-tense statements ("forges: … / does not forge: …").

## 3. T9b — the adversarial eval harness (`eval/`)

**Goal:** a small, standalone Go program that drives fingerprintproxy across
its full profile set against a configurable "continuity scorer" HTTP
endpoint, and prints a reproducible per-profile score table. It must be
useful against a mock endpoint in CI and against a real endpoint only when a
human opts in.

**Files touched (new):**
- `eval/main.go` — package `main`, the harness. Single file, no
  sub-packages: this is a small CLI tool, not a library other code needs to
  import, so there's nothing to gain from a `cmd/` split.
- `eval/main_test.go` — unit tests using `net/http/httptest` and a hardcoded,
  deterministic fixture (no network, no external endpoint).

**Interface:**
```go
// Requester performs one HTTP round trip through a running fingerprintproxy
// instance, using profile as the X-Fingerprint header value, against target.
type Requester func(profile, target string) (*http.Response, error)

// Scorer extracts a continuity score from the target's response body.
type Scorer func(resp *http.Response) (float64, error)

// Result is one profile's outcome.
type Result struct {
    Profile string
    Score   float64
    Err     string // set instead of Score on request/decode failure
}

// Run drives every profile in names against target, sorted by profile name
// for a reproducible table.
func Run(names []string, target string, request Requester, score Scorer) []Result

// JSONScorer decodes {"continuity_score": <float>} from resp.Body.
func JSONScorer(resp *http.Response) (float64, error)

// Table renders results as a markdown table.
func Table(results []Result) string
```

The profile list itself is **not** duplicated inside `eval/` — the harness
shells out to the fingerprintproxy binary's own `-list` output
(`parseProfileListOutput` parses it; a separate, exec-free unit test covers
the parsing logic against a fixed sample string). This keeps `profiles.go`
as the single source of truth; the harness can never drift from it the way
the README numbers did.

**What is measured:** for each profile name, one HTTP request is made
through the running fingerprintproxy (`-proxy localhost:8080` by default)
carrying that profile in `X-Fingerprint`, against `-target` (the
continuity-scoring endpoint). The scorer function decodes a numeric
`continuity_score` from the JSON response body. The harness records that
number (or the error, if the request/decode failed) per profile and renders
a sorted markdown table — nothing is aggregated, extrapolated, or averaged
into a single headline figure by the harness itself; any such summary is a
human's job when writing up a specific run (see T9c).

**How the number stays honest:** the harness performs a real HTTP call per
profile and reports exactly what the target returned, or reports an explicit
error — it never fabricates or interpolates a score. Real-endpoint runs are
strictly opt-in:
- Dry run is the default: with no `-real` flag and no `EVAL_REAL=1`, the
  program only prints what it *would* do (profile count, target, proxy
  address) and exits 0 — no network call beyond invoking `-list`.
- A real run additionally requires `-target`/`EVAL_TARGET_URL` to be set.
- No secrets are hardcoded anywhere; `-target` is the only endpoint
  configuration, and it is caller-supplied.

**CI verification:** `eval/main_test.go` spins up an `httptest.Server` as the
mock scorer, serving a hardcoded `map[string]float64` fixture keyed by
profile name (plus one unknown-profile case verified to produce an `Err`),
and asserts `Run` reproduces that fixture exactly. This test runs under the
existing `go test ./...` in `.github/workflows/ci.yml` — no CI workflow
changes are needed, since that job already covers every package in the
module.

**Acceptance criteria:**
- `go build ./...` succeeds with `eval/` included.
- `go test ./...` passes, including the new mock-scorer test, deterministically
  and without network access or an external target.
- Running `go run ./eval` with no flags does not make any external network
  call and exits 0.
- Running `go run ./eval -real` without `-target`/`EVAL_TARGET_URL` exits
  non-zero with a clear error, never silently no-ops into a fake result.

## 4. T9c — cost-to-evade doc (pending measurement)

**Files touched (new):** `docs/cost-to-evade.md`.

**Content:** states the cost-to-evade *framework* — cite the BotGuard SoK
("Operator Synthesis", `tomkabel/google-botguard-security-research`) §5 cost
model (VLM inference pricing, proxy-supply elasticity, latency overhead) by
reference, and describe how this repo's harness output would plug into it
(TLS-layer cost ≈ near-zero given this proxy is free/open-source; the
*additional* cost of full multi-layer coherence — residential IP path +
matched kernel TCP stack — is the open variable). It explicitly states:

> No real-endpoint harness run has been executed as of this writing. The
> continuity-score-movement number and the resulting cost-to-evade figure are
> **pending measurement** — they are not published here because they have
> not been measured. This document will be updated with a dated, method-cited
> result only after an actual `eval/` run against a real scorer endpoint.

No numeric result is invented anywhere in this document.

**Acceptance criteria:** the doc exists, cites the SoK by repo+section
reference (not by a quoted number, since this agent has not re-verified the
paper's exact section numbering against the live repo in this run), and
contains no fabricated score/cost figure — only the framework and an
explicit pending-measurement placeholder.

## 5. Definition of done (recap, tied to acceptance criteria above)

- [ ] Profile count consistent at **72** everywhere in `README.md`, with the
      counting command quoted.
- [ ] README has a "what is/isn't forgeable" section using only verified
      capability claims.
- [ ] `eval/` package exists, builds, and its mock-scorer test passes in
      `go test ./...` (i.e., in the existing CI workflow) deterministically.
- [ ] `docs/cost-to-evade.md` exists, cites the SoK cost framework by
      reference, and marks the actual number "pending measurement" — no
      fabricated figure.
- [ ] `go build ./...` and `go test ./...` both pass before every commit.

## 6. PR sequencing

Given the total diff across these four tasks is small (a README edit, two
short docs, and one ~150-line `eval/` package with its test), this plan is
implemented as **one combined PR** rather than four separate ones — a
judgment call permitted by the handoff's "one PR per phase (or one combined
PR if the total diff is small)" instruction. The PR body enumerates each task
separately with its own verification, so reviewers can evaluate them
independently even though they land together.
