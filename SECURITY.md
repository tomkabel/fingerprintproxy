# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/tomkabel/fingerprintproxy/security/advisories/new). Please don't open public issues for security problems.

Include the affected version or commit, steps to reproduce, and the impact you observed.

## Supported versions

Only the latest release and `main` receive fixes.

## Known design properties

These are intended behaviour, not vulnerabilities:

- HTTPS interception uses goproxy's built-in CA, whose private key is public. Never trust it outside an isolated test setup.
- `-insecure` disables upstream certificate verification.
