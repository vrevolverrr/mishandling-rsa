// rsa.go holds the RSA primitives: building a private key from chosen primes and the PKCS#1 v1.5 message encoding.

package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"slices"
)

func GeneratePossiblyUnsafeRSAKeyFromPrimes(p, q *big.Int) (*rsa.PrivateKey, error) {
	// n = p^2 has phi = p(p-1), not (p-1)^2, so d below would be wrong
	if p.Cmp(q) == 0 {
		return nil, errors.New("p == q")
	}

	one := big.NewInt(1)

	p, q = new(big.Int).Set(p), new(big.Int).Set(q)
	n := new(big.Int).Mul(p, q)

	phiP := new(big.Int).Sub(p, one)
	phiQ := new(big.Int).Sub(q, one)
	phi := new(big.Int).Mul(phiP, phiQ)

	e := big.NewInt(65537)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, errors.New("e has no inverse mod phi: e divides p-1 or q-1")
	}

	key := &rsa.PrivateKey{
		N: n, E: int(e.Int64()),
		D:      d,
		Primes: []*big.Int{p, q},
	}

	// skip key.Validate() cuz it will always fail with unsafe primes
	// manually precompute since Precompute() also validates
	key.Precomputed.Dp = new(big.Int).Mod(d, new(big.Int).Sub(p, one))
	key.Precomputed.Dq = new(big.Int).Mod(d, new(big.Int).Sub(q, one))
	key.Precomputed.Qinv = new(big.Int).ModInverse(q, p)

	return key, nil
}

// DER DigestInfo prefix for SHA-256 (RFC 8017 §9.2, note 1).
var sha256DigestInfo = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

// encodePKCS1v15SHA256 returns the EMSA-PKCS1-v1_5 encoding of SHA-256(msg)
// for a k-byte modulus: 0x00 || 0x01 || 0xFF... || 0x00 || DigestInfo || hash.
func encodePKCS1v15SHA256(msg []byte, k int) ([]byte, error) {
	h := sha256.Sum256(msg)
	t := slices.Concat(sha256DigestInfo, h[:])
	if k < len(t)+11 {
		return nil, errors.New("modulus too short for PKCS#1 v1.5")
	}

	em := make([]byte, k)
	em[1] = 0x01
	for i := 2; i < k-len(t)-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-len(t):], t)
	return em, nil
}

// encodeMessage returns the integer m that RSA signs for signingString under pub (RFC 8017 §8.2.1, OS2IP of the EMSA-PKCS1-v1_5 encoding).
func encodeMessage(pub *rsa.PublicKey, signingString string) (*big.Int, error) {
	em, _ := encodePKCS1v15SHA256([]byte(signingString), pub.Size())
	return new(big.Int).SetBytes(em), nil
}
