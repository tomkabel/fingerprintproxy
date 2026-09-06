# Cost to Evade

**Status: pending measurement.** This document states the cost framework
this repo's eval harness (`eval/`, see `docs/eval-harness-plan.md`) is built
to feed. It does **not** publish a continuity-score-movement number or a
dollar cost-to-evade figure, because no real-endpoint harness run has been
executed as of this writing. A fabricated number would violate this repo's
own working rules; this placeholder exists so the framework is documented
honestly ahead of that measurement.

## Framework

The economic framing follows the cost-to-evade model in the BotGuard SoK
("Operator Synthesis", `tomkabel/google-botguard-security-research`) §5,
which prices evasion across three components: VLM/inference cost, proxy
(residential IP) supply elasticity and pricing, and latency overhead imposed
by routing through that infrastructure. That paper explicitly scopes
server-side TLS fingerprinting out of its analysis (§1.2/§3.1) — this
document is the piece it excludes, applied to `fingerprintproxy`.

Mapped onto what this repo actually does and does not do (see
`README.md` → "What This Proxy Can and Cannot Forge"):

- **TLS-layer spoofing cost:** near-zero. `fingerprintproxy` is free,
  open-source, and this repo is itself the existence proof — running any of
  its 72 profiles costs nothing beyond compute already in use.
- **Additional cost for full multi-layer coherence:** the open variable.
  Matching a spoofed TLS profile with a *consistent* TCP/IP kernel stack
  (correct TTL, window size, option order) and a residential (rather than
  datacenter) network path is not something this proxy provides, and is
  where any real cost-to-evade figure would have to come from — e.g. the
  price of residential proxy bandwidth, and the engineering cost of running
  the spoofing client on a kernel/network stack that matches the claimed
  browser/OS combination.

## What the measurement will look like once run

Per `docs/eval-harness-plan.md` §3, an actual run of `eval/` against a real
continuity-scoring endpoint produces a per-profile table of `X-Fingerprint`
value → continuity score. A future update to this document will report,
with a date and the exact `eval/` invocation used:

- the score movement observed across the profile set (or per-profile, if
  movement is not uniform),
- whether that run additionally routed through a residential proxy and/or a
  matched kernel network stack, and what that cost, and
- the resulting cost-to-evade figure, computed via the SoK §5 framework
  above, method and date clearly stated.

Until that run happens, treat any number attached to this repo's evasion
capability as **unmeasured**.
