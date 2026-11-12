// jwt.go adds the helpers that create and verify RS256 tokens on top of golang-jwt.

package main

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

// unsafeFaultyRS256 signs by raw CRT modexp instead of crypto/rsa, which rejects unsafe (factored) keys.
// See SignMessageWithFaultyCRT for the injected fault.
type unsafeFaultyRS256 struct{ *jwt.SigningMethodRSA }

var SigningMethodFaultyRS256 = unsafeFaultyRS256{jwt.SigningMethodRS256}

func (unsafeFaultyRS256) Sign(signingString string, key any) ([]byte, error) {
	k, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, jwt.ErrInvalidKeyType
	}

	m, err := encodeMessage(&k.PublicKey, signingString)
	if err != nil {
		return nil, err
	}

	s := SignMessageWithFaultyCRT(k, m)

	// verify the signature and recompute without CRT on failure
	// if new(big.Int).Exp(s, big.NewInt(int64(k.E)), k.N).Cmp(m) != 0 {
	// 	s = new(big.Int).Exp(m, k.D, k.N)
	// }

	sig := s.FillBytes(make([]byte, k.Size()))

	return sig, nil
}

// signModQ returns the correct m^dq mod q and the same value with bit 0 flipped (the injected fault).
func signModQ(key *rsa.PrivateKey, m *big.Int) (sq, faulty *big.Int) {
	sq = new(big.Int).Exp(m, key.Precomputed.Dq, key.Primes[1])
	faulty = new(big.Int).SetBit(sq, 0, sq.Bit(0)^1)

	return sq, faulty
}

// SignMessageWithFaultyCRT signs an encoded message m with the RSA key using the Chinese Remainder Theorem (CRT).
func SignMessageWithFaultyCRT(key *rsa.PrivateKey, m *big.Int) (s *big.Int) {
	p, q := key.Primes[0], key.Primes[1]
	n, dp := key.N, key.Precomputed.Dp

	sp := new(big.Int).Exp(m, dp, p)
	_, sq := signModQ(key, m)

	qInv := new(big.Int).ModInverse(q, p)
	pInv := new(big.Int).ModInverse(p, q)

	ep := new(big.Int).Mul(qInv, q) // q⁻¹ * q (mod p)
	eq := new(big.Int).Mul(pInv, p) // p⁻¹ * p (mod q)

	spep := new(big.Int).Mul(sp, ep)
	sqeq := new(big.Int).Mul(sq, eq)

	s = new(big.Int).Add(spep, sqeq)
	return s.Mod(s, n)
}

// CreateRS256Token mints a JWT token holding claims and signs with key with the RS256 scheme.
// It's re-implemented because the rsa library rejects signing with unsafe keys.
func CreateRS256Token(claims jwt.MapClaims, key *rsa.PrivateKey) (jwtString string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signingString, err := token.SigningString()
	if err != nil {
		return "", err
	}

	m, _ := encodeMessage(&key.PublicKey, signingString)

	s := new(big.Int).Exp(m, key.D, key.N)
	sig := s.FillBytes(make([]byte, key.Size()))

	return signingString + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyRS256Token(tokenString string, pubKey *rsa.PublicKey) (*jwt.Token, error) {
	keyFunc := func(*jwt.Token) (any, error) {
		return pubKey, nil
	}

	return jwt.Parse(tokenString, keyFunc, jwt.WithValidMethods([]string{"RS256"}))
}
