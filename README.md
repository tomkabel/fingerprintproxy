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
- **Fallback to User-Agent parsing** when no `X-Fingerprint` header is present
- **Transport pooling** for connection reuse per fingerprint profile
- **MITM support** for transparent HTTPS interception
- **Support for 80+ browser profiles** (Chrome, Firefox, Safari, etc.)

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
| `safari` | `safari_18_5`  |
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
-v                   Enable verbose logging (default: true)
-list                 List available profiles and exit
```

## Available Profiles

Run `go run main.go -list` to see all 80+ available profiles including:

- `chrome_103` through `chrome_133` (including PSK variants)
- `firefox_102` through `firefox_147` (including PSK variants)
- `safari_18_5`, `safari_ios_18_5`
- `opera_89`, `opera_91`

## Environment Variables

| Variable | Description |
|----------|-------------|
| `HTTP_PROXY` | Upstream HTTP proxy URL |
| `HTTPS_PROXY` | Upstream HTTPS proxy URL |
| `NO_PROXY` | Hosts to bypass proxy |

## License

MIT License - A standalone TLS fingerprinting forward proxy.
