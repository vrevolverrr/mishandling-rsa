package main

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

type Server struct{ key *rsa.PrivateKey }

func NewServer() (*Server, error) {
	p, q := GenerateUnsafe1024BitPrimes()
	key, err := GeneratePossiblyUnsafeRSAKeyFromPrimes(p, q)
	if err != nil {
		return nil, err
	}

	// generate secure key
	// key, _ := rsa.GenerateKey(rand.Reader, 2048)

	return &Server{key: key}, nil
}

func (s *Server) PublicKey() *rsa.PublicKey { return &s.key.PublicKey }

func (s *Server) IssueFaultyToken(claims jwt.MapClaims) (string, error) {
	return jwt.NewWithClaims(SigningMethodFaultyRS256, claims).SignedString(s.key)
}
