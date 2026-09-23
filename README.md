# Fingerprint Proxy

[![CI](https://github.com/tomkabel/fingerprintproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/tomkabel/fingerprintproxy/actions/workflows/ci.yml)
[![Lint](https://github.com/tomkabel/fingerprintproxy/actions/workflows/lint.yml/badge.svg)](https://github.com/tomkabel/fingerprintproxy/actions/workflows/lint.yml)
[![Security](https://github.com/tomkabel/fingerprintproxy/actions/workflows/security.yml/badge.svg)](https://github.com/tomkabel/fingerprintproxy/actions/workflows/security.yml)
[![Dependencies](https://github.com/tomkabel/fingerprintproxy/actions/workflows/dependencies.yml/badge.svg)](https://github.com/tomkabel/fingerprintproxy/actions/workflows/dependencies.yml)
[![Release](https://github.com/tomkabel/fingerprintproxy/actions/workflows/release.yml/badge.svg)](https://github.com/tomkabel/fingerprintproxy/actions/workflows/release.yml)
[![Go Version](https://img.shields.io/badge/Go-1.25-blue)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

A standalone TLS fingerprinting forward proxy that applies browser TLS fingerprints to outbound requests based on the `X-Fingerprint` header.

---

## Overview

This proxy acts as a plug-and-play forward proxy that can be used via `HTTP_PROXY`/`HTTPS_PROXY` environment variables. It routes requests through a pool of fingerprinted transports, selecting the appropriate browser fingerprint based on request headers.

## Features

- **Per-request fingerprint selection** via `X-Fingerprint` header
- **Transport pooling** for connection reuse per fingerprint profile
- **MITM support** for transparent HTTPS interception
- **Support for 72 browser profiles** (Chrome, Firefox, Safari, Opera, and several mobile/app-specific profiles)

## Quick Start

### Run the proxy

```bash
cd fingerprintproxy
go run main.go
```

### Use as forward proxy

```bash
# With default Chrome 133 fingerprint
HTTP_PROXY=http://localhost:8080 curl https://example.com

# With explicit fingerprint via header
curl -x http://localhost:8080 -H "X-Fingerprint: firefox_147" https://example.com

# HTTPS via proxy
HTTPS_PROXY=http://localhost:8080 curl -k https://example.com
```

### List available profiles

```bash
go run main.go -list
```

## X-Fingerprint Header

The proxy reads the `X-Fingerprint` header to determine which browser profile to use:

```bash
# Use Firefox fingerprint
curl -x http://localhost:8080 -H "X-Fingerprint: firefox_147" https://example.com

# Use Safari iOS fingerprint
curl -x http://localhost:8080 -H "X-Fingerprint: safari_ios_18_5" https://example.com

# Use short aliases
curl -x http://localhost:8080 -H "X-Fingerprint: chrome" https://example.com
```

### Supported Aliases

| Alias    | Resolves To    |
|----------|----------------|
| `chrome` | `chrome_133`   |
| `firefox`| `firefox_147`  |
| `safari` | `safari_16_0`  |
| `edge`   | `chrome_133`   |
| `ios`    | `safari_ios_18_5` |
| `mobile` | `chrome_133`   |

## Integration with Main Proxy

### Architecture

```
┌─────────────────┐      ┌──────────────────────────────────────┐
│  Main goproxy   │      │         Fingerprint Proxy            │
│  (no fp needed) │──────│                                      │
│                 │      │  X-Fingerprint: chrome_133           │
└─────────────────┘      │  X-Fingerprint: firefox_147          │
                         │  X-Fingerprint: safari_ios_18_5      │
                         └──────────────────────────────────────┘
                                            │
                                            ▼
                               ┌──────────────────────┐
                               │   Target Server      │
                               └──────────────────────┘
```

### Usage with Main Proxy

```go
package main

import (
    "net/http"
    "github.com/elazarl/goproxy"
)

func main() {
    proxy := goproxy.NewProxyHttpServer()

    // Configure main proxy to use fingerprint proxy as upstream
    transport := &http.Transport{
        Proxy: http.ProxyURL(parseURL("http://localhost:8080")),
    }
    proxy.Tr = transport

    http.ListenAndServe(":8080", proxy)
}
```

### Per-Request Fingerprint Selection

```bash
# Route requests to different fingerprints based on path or header
curl -x http://localhost:8080 \
     -H "X-Fingerprint: chrome_133" \
     https://api.example.com/v1

curl -x http://localhost:8080 \
     -H "X-Fingerprint: firefox_147" \
     https://api.example.com/v2
```

## Command-Line Options

```
-http :8080           HTTP proxy listen address (default: :8080)
-https :8081          HTTPS transparent proxy listen address (default: :8081)
-profile chrome_133   Default fingerprint profile (default: chrome_133)
-v                   Enable verbose logging (default: false)
-list                 List available profiles and exit
```

## Available Profiles

There are **72 profiles** registered in `profiles.go` (64 base profiles + 8
`_psk` variants). This is a verified count, not an estimate — reproduce it
yourself:

```bash
awk '/profileRegistry = map/,/^}/' profiles.go | grep -c '":'          # 72 total
awk '/profileRegistry = map/,/^}/' profiles.go | grep '":' | grep -c '_psk"'  # 8 PSK variants
```

Run `go run main.go -list` to see all 72 available profiles, including:

- `chrome_103` through `chrome_146` (including PSK variants)
- `firefox_102` through `firefox_147` (including PSK variants)
- `safari_15_6_1` through `safari_ios_26_0`
- `opera_89` through `opera_91`
- a handful of mobile/app-specific profiles (`okhttp4_android_*`, `zalando_*`, `nike_*`, `mesh_*`, `mms_ios*`, `confirmed_*`, `cloudscraper`)

Note: `chrome_133` is the *default profile name* (see `-profile` below), not
a count — don't confuse the two.

## What This Proxy Can and Cannot Forge

Be honest about the boundary of what TLS-fingerprint spoofing actually
covers, so this isn't mistaken for full traffic-fingerprint evasion:

**Forges:**
- The TLS ClientHello / JA3 / JA4 fingerprint, per profile — cipher suite
  list, extension order, supported curves/point formats, ALPN, and similar
  handshake-level details (via `tls-client`/`utls`).

**Does NOT forge:**
- **TCP SYN kernel fields** — TTL, window size, TCP option order. These come
  from the OS network stack the proxy process runs on, not from anything
  `tls-client` controls.
- **H2/H3 frame timing and behavior** — static settings values can be sent,
  but the runtime cadence/prioritization pattern of a real browser's frames
  over time is not reproduced.
- **WebSocket cadence** — out of scope; this proxy only handles HTTP(S).
- **Cross-layer coherence** — a spoofed Chrome ClientHello arriving over a
  Linux-container TCP stack, possibly relayed through a residential proxy
  with its own TTL/window signature, is internally inconsistent even though
  each individual layer looks plausible on its own.

Single-layer (TLS-only) spoofing is cheap — this repo is a working example
of that. Coherent spoofing across all of the layers above is a materially
harder and more expensive problem, which is exactly why detection strategies
that combine multiple independent signals (rather than trusting any one
layer) are harder to defeat than TLS fingerprinting alone would suggest.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `HTTP_PROXY` | Upstream HTTP proxy URL |
| `HTTPS_PROXY` | Upstream HTTPS proxy URL |
| `NO_PROXY` | Hosts to bypass proxy |

## License

MIT License - A standalone TLS fingerprinting forward proxy.
