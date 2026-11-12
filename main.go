package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	bold   = "\033[1m"
	dim    = "\033[2m"
	green  = "\033[1;32m"
	cyan   = "\033[1;36m"
	yellow = "\033[1;33m"
	red    = "\033[1;31m"
	reset  = "\033[0m"
)

func section(title string) {
	fmt.Printf("\n%s=== %s ===%s\n", bold, title, reset)
}

func step(n int, label string) {
	fmt.Printf("\n%s[%d]%s %s\n", dim, n, reset, label)
}

func forgeAndVerify(claims jwt.MapClaims, key *rsa.PrivateKey, pub *rsa.PublicKey) {
	token, err := CreateRS256Token(claims, key)
	if err != nil {
		fmt.Printf("%sfailed to forge token: %v%s\n", red, err, reset)
		return
	}
	t, err := VerifyRS256Token(token, pub)
	if err != nil {
		fmt.Printf("%sserver rejected token: %v%s\n", red, err, reset)
		return
	}
	c := t.Claims.(jwt.MapClaims)
	fmt.Printf("%sVerified by server's public key: sub=%v admin=%v%s\n", green, c["sub"], c["admin"], reset)
	fmt.Printf("%s%s%s\n", dim, token, reset)
}

func main() {
	badClaims := jwt.MapClaims{"sub": "alice", "admin": true}
	server, _ := NewServer()
	pub := server.PublicKey()

	section("Attack 1: Fermat Factorization")

	step(1, "Server generates 2048-bit RSA key")
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	fmt.Printf("%s%s", dim, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	step(2, "Alice runs Fermat factorization on N")

	start := time.Now()
	maxIters := 100_000
	p1, q1, iters, ok := FermatFactorize(pub.N, maxIters)
	elapsed := time.Since(start)

	if !ok {
		fmt.Printf("%sfailed after %d iterations\n", red, maxIters)
	} else {
		fmt.Printf("%sFactored N in %d iterations (%s)%s\n", yellow, iters, elapsed, reset)
		printKey(p1, q1)

		step(3, "Alice forges malicious JWT {admin: true}")
		recoveredKey, _ := GeneratePossiblyUnsafeRSAKeyFromPrimes(p1, q1)
		forgeAndVerify(badClaims, recoveredKey, pub)

		return
	}

	section("Attack 2: Lenstra's RSA-CRT Fault Attack")

	fmt.Printf("  N = %s (%d bits)\n", truncated(pub.N), pub.N.BitLen())

	step(2, "Server issues alice a normal token but with faulty signature")
	faultyToken, _ := server.IssueFaultyToken(jwt.MapClaims{"sub": "alice", "admin": false})
	parsed, parts, _ := jwt.NewParser().ParseUnverified(faultyToken, jwt.MapClaims{})

	// JWT header.payload.signature
	signingString := parts[0] + "." + parts[1]
	faultySig := new(big.Int).SetBytes(parsed.Signature)
	fmt.Printf("  s~ = %s (%d bits)\n", truncated(faultySig), faultySig.BitLen())
	// recover M by encoding the original signature
	m, _ := encodeMessage(pub, signingString)

	sq, sqFaulty := signModQ(server.key, m)
	sqStr, sqFaultyStr := truncatedPair(sq, sqFaulty)
	fmt.Printf("  sq  = %s\n", sqStr)
	fmt.Printf("  sq~ = %s\n", sqFaultyStr)

	step(3, "Alice checks her token against the server's public key")
	if _, err := VerifyRS256Token(faultyToken, pub); err != nil {
		fmt.Printf("%s%v%s\n", red, err, reset)
	} else {
		fmt.Printf("%ssignature valid%s\n", green, reset)
	}

	step(4, "Alice computes gcd(s~^e − m, N)")
	start = time.Now()

	e := big.NewInt(int64(pub.E))
	check := new(big.Int).Exp(faultySig, e, pub.N)
	diff := new(big.Int).Mod(new(big.Int).Sub(check, m), pub.N)

	p2 := new(big.Int).GCD(nil, nil, diff, pub.N)
	q2 := new(big.Int).Div(pub.N, p2)

	elapsed = time.Since(start)

	// gcd of 1 or N means the fault hit both or neither paths, no leak
	if p2.Cmp(big.NewInt(1)) == 0 || p2.Cmp(pub.N) == 0 {
		fmt.Printf("%sgcd = %s (%d bits) → no factor, attack failed (%s)%s\n", green, truncated(p2), p2.BitLen(), elapsed, reset)
		return
	}

	fmt.Printf("%sgcd = %s (%d bits) → found p! (%s)%s\n", cyan, truncated(p2), p2.BitLen(), elapsed, reset)
	fmt.Printf("%sq = N/p = %s (%d bits)%s\n", yellow, truncated(q2), q2.BitLen(), reset)

	step(5, "Alice reconstructs server's private key")
	recoveredKey, err := GeneratePossiblyUnsafeRSAKeyFromPrimes(p2, q2)
	if err != nil {
		fmt.Printf("%sfailed: %v\n", red, err)
		return
	}
	privDER := x509.MarshalPKCS1PrivateKey(recoveredKey)
	fmt.Printf("%s%s", dim, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))

	step(6, "Alice forges malicious JWT {admin: true}")
	forgeAndVerify(badClaims, recoveredKey, pub)
}
