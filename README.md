# fingerprintproxy

[![CI](https://github.com/tomkabel/fingerprintproxy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tomkabel/fingerprintproxy/actions/workflows/ci.yml)
[![Lint](https://github.com/tomkabel/fingerprintproxy/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/tomkabel/fingerprintproxy/actions/workflows/lint.yml)
[![Security](https://github.com/tomkabel/fingerprintproxy/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/tomkabel/fingerprintproxy/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/tomkabel/fingerprintproxy/badge)](https://scorecard.dev/viewer/?uri=github.com/tomkabel/fingerprintproxy)
[![Go version](https://img.shields.io/github/go-mod/go-version/tomkabel/fingerprintproxy)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A forward proxy that sends your outbound HTTPS requests with a real browser's TLS and HTTP/2 fingerprint. You pick the browser per request with one header.

```bash
curl -k -x http://localhost:8080 -H "X-Fingerprint: firefox" https://tls.peet.ws/api/all
```

The target sees a Firefox 147 ClientHello (JA3/JA4) instead of curl's. The proxy builds on [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) and [elazarl/goproxy](https://github.com/elazarl/goproxy).

> [!WARNING]
> fingerprintproxy decrypts HTTPS traffic (MITM) with goproxy's **built-in, publicly known CA**. Anyone can mint certificates from that key. Run the proxy only on machines and networks you control, keep it off public interfaces, and never add its CA to a system or browser trust store.

## Contents

- [Features](#features)
- [Install](#install)
- [Usage](#usage)
- [Request headers](#request-headers)
- [Profiles](#profiles)
- [Command-line flags](#command-line-flags)
- [Chaining behind another proxy](#chaining-behind-another-proxy)
- [How it works](#how-it-works)
- [Development](#development)
- [Security](#security)
- [Responsible use](#responsible-use)

## Features

- **Per-request fingerprints** through the `X-Fingerprint` header, with a configurable default.
- **72 profiles**: Chrome, Firefox, Safari (macOS, iOS, iPadOS), Opera, OkHttp on Android, and several mobile-app clients.
- **Per-request upstream proxy** through `X-FP-Proxy` (HTTP or SOCKS5, with credentials). The proxy redacts passwords before logging.
- **Transport cache** keyed by profile and upstream, with a TTL and size limit, so repeat requests reuse connections.
- **Two listeners**: an explicit forward proxy (`:8080`) and an SNI-based transparent HTTPS listener (`:8081`).
- **Graceful shutdown** on `SIGINT`/`SIGTERM`.

## Install

You need Go 1.26 or newer.

```bash
go install github.com/tomkabel/fingerprintproxy@latest
```

Or build from source:

```bash
git clone https://github.com/tomkabel/fingerprintproxy
cd fingerprintproxy
go build -o fingerprintproxy .
```

Tagged releases publish binaries for Linux, macOS and Windows (amd64 and arm64) on the [Releases](https://github.com/tomkabel/fingerprintproxy/releases) page. Each release carries a build provenance attestation you can check with the GitHub CLI:

```bash
gh attestation verify fingerprintproxy_*.tar.gz --repo tomkabel/fingerprintproxy
```

## Usage

Start the proxy:

```bash
fingerprintproxy            # HTTP proxy on :8080, transparent HTTPS on :8081
fingerprintproxy -v         # verbose logging
fingerprintproxy -list      # print every profile and exit
```

Send requests through it. Use `-k` (or your client's equivalent) because the proxy re-signs HTTPS with its own CA:

```bash
# Default profile (chrome_133)
curl -k -x http://localhost:8080 https://example.com

# Pick a profile or alias per request
curl -k -x http://localhost:8080 -H "X-Fingerprint: safari_ios_18_5" https://example.com

# Route this request through an upstream proxy as well
curl -k -x http://localhost:8080 \
     -H "X-Fingerprint: chrome_146" \
     -H "X-FP-Proxy: socks5://user:pass@10.0.0.5:1080" \
     https://example.com
```

For tools that read proxy environment variables, set the lowercase forms (curl ignores uppercase `HTTP_PROXY`):

```bash
export http_proxy=http://localhost:8080 https_proxy=http://localhost:8080
```

## Request headers

| Header | Purpose | Example |
|---|---|---|
| `X-Fingerprint` | Profile name or alias for this request. Case-insensitive. Unknown values fall back to the default profile and log a warning. | `firefox_147`, `ios` |
| `X-FP-Proxy` | Upstream proxy for this request. | `http://user:pass@host:3128`, `socks5://host:1080` |

The proxy strips both headers before forwarding, so the target never sees them.

### Aliases

| Alias | Profile |
|---|---|
| `chrome`, `chromium`, `edge`, `mobile` | `chrome_133` |
| `firefox`, `ff` | `firefox_147` |
| `safari` | `safari_16_0` |
| `ios` | `safari_ios_18_5` |

## Profiles

`fingerprintproxy -list` prints all 72 profiles and whether each carries HTTP/3 settings or uses TLS session resumption (PSK).

<details>
<summary>Full profile list</summary>

| Family | Profiles |
|---|---|
| Chrome (23) | `chrome_103`–`chrome_111`, `chrome_116_psk`, `chrome_116_psk_pq`, `chrome_117`, `chrome_120`, `chrome_124`, `chrome_130_psk`, `chrome_131`, `chrome_131_psk`, `chrome_133`, `chrome_133_psk`, `chrome_144`, `chrome_144_psk`, `chrome_146`, `chrome_146_psk` |
| Firefox (15) | `firefox_102`, `firefox_104`, `firefox_105`, `firefox_106`, `firefox_108`, `firefox_110`, `firefox_117`, `firefox_120`, `firefox_123`, `firefox_132`, `firefox_133`, `firefox_135`, `firefox_146_psk`, `firefox_147`, `firefox_147_psk` |
| Safari (10) | `safari_15_6_1`, `safari_16_0`, `safari_ipad_15_6`, `safari_ios_15_5`, `safari_ios_15_6`, `safari_ios_16_0`, `safari_ios_17_0`, `safari_ios_18_0`, `safari_ios_18_5`, `safari_ios_26_0` |
| Opera (3) | `opera_89`, `opera_90`, `opera_91` |
| OkHttp / Android (7) | `okhttp4_android_7` – `okhttp4_android_13` |
| App clients (14) | `cloudscraper`, `confirmed_android`, `confirmed_ios`, `mesh_android`, `mesh_android_2`, `mesh_ios`, `mesh_ios_2`, `mms_ios`, `mms_ios_2`, `mms_ios_3`, `nike_android`, `nike_ios`, `zalando_android`, `zalando_ios` |

</details>

## Command-line flags

| Flag | Default | Description |
|---|---|---|
| `-http` | `:8080` | Forward proxy listen address |
| `-https` | `:8081` | Transparent HTTPS listen address (needs SNI) |
| `-profile` | `chrome_133` | Default profile when no `X-Fingerprint` header is present |
| `-cache-ttl` | `30m` | How long an idle cached transport lives |
| `-cache-max` | `20` | Maximum cached transports |
| `-insecure` | `false` | Skip upstream certificate verification. For testing only. |
| `-v` | `false` | Verbose logging |
| `-list` | | Print profiles and exit |

To bind only to localhost, pass `-http 127.0.0.1:8080 -https 127.0.0.1:8081`.

## Chaining behind another proxy

If you already run a goproxy-based proxy, point both its HTTP transport and its CONNECT dialer at fingerprintproxy:

```go
package main

import (
	"log"
	"net/http"
	"net/url"

	"github.com/elazarl/goproxy"
)

func main() {
	upstream, err := url.Parse("http://localhost:8080") // fingerprintproxy
	if err != nil {
		log.Fatal(err)
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr = &http.Transport{Proxy: http.ProxyURL(upstream)}         // plain HTTP
	proxy.ConnectDial = proxy.NewConnectDialToProxy(upstream.String()) // HTTPS CONNECT

	log.Fatal(http.ListenAndServe(":9090", proxy))
}
```

Clients keep setting `X-Fingerprint` on their requests. Your front proxy passes it through, and fingerprintproxy reads it after decrypting the tunnel.

## How it works

```mermaid
flowchart LR
    C[Client<br/>curl, scraper, app] -- "CONNECT / HTTP<br/>X-Fingerprint, X-FP-Proxy" --> P
    subgraph P[fingerprintproxy]
        direction TB
        M[goproxy MITM<br/>decrypts with built-in CA] --> R[Pick profile<br/>header, alias or default]
        R --> T[Transport cache<br/>key = profile + upstream]
    end
    T -- "browser TLS ClientHello<br/>+ HTTP/2 settings" --> U{X-FP-Proxy set?}
    U -- yes --> X[Upstream proxy] --> S[Target server]
    U -- no --> S
```

1. goproxy accepts the request. For HTTPS it terminates TLS with a certificate signed by its built-in CA.
2. The handler resolves the profile from `X-Fingerprint` (exact name, then alias, then the default).
3. The transport cache returns or creates a tls-client transport for that profile and upstream proxy.
4. tls-client opens the outbound connection with the profile's TLS ClientHello and HTTP/2 settings.

## Development

```bash
go test -short ./...       # unit tests, no network
go test -race ./...        # adds live JA3 checks against tls.peet.ws
golangci-lint run          # config in .golangci.yml
govulncheck ./...
```

The integration tests compare JA3 hashes reported by tls.peet.ws. They fail on networks that intercept TLS (corporate proxies, some sandboxes), because the remote end then sees the interceptor's fingerprint.

CI runs build and tests on both supported Go releases, cross-compiles six targets, and runs golangci-lint, actionlint, zizmor, govulncheck, gosec, CodeQL and OpenSSF Scorecard. Dependabot opens grouped weekly updates for Go modules and GitHub Actions. All actions are pinned to commit SHAs.

To cut a release, push a `v*` tag. GoReleaser builds the archives and the workflow attests their checksums.

## Security

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/tomkabel/fingerprintproxy/security/advisories/new) rather than public issues.

## Responsible use

Use fingerprintproxy for testing your own bot-detection and TLS-fingerprinting defenses, for research, and for interoperability work. Follow the terms of service of the sites you contact and the law where you operate.

## License

[MIT](LICENSE)
