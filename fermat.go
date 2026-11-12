package main

import (
	"crypto/rand"
	"math/big"
)

// FermatFactorize attempts to find a, b s.t. n = a^2 - b^2 within maxIter iterations, returns a - b, a + b (so p <= q).
func FermatFactorize(n *big.Int, maxIter int) (p, q *big.Int, iters int, ok bool) {
	one := big.NewInt(1)

	var a, b, a2, b2, t big.Int

	// a0 = ceil(sqrt(n)) = floor(sqrt(n - 1)) + 1
	a.Sub(n, one)
	a.Sqrt(&a)
	a.Add(&a, one)

	for i := range maxIter {
		// t = a^2 - n
		a2.Mul(&a, &a)
		t.Sub(&a2, n)

		// b = floor(sqrt(t))
		b.Sqrt(&t)
		b2.Mul(&b, &b)

		if t.Cmp(&b2) == 0 {
			return new(big.Int).Sub(&a, &b), new(big.Int).Add(&a, &b), i + 1, true
		}

		a.Add(&a, one)
	}

	return nil, nil, maxIter, false
}

// dividesPMinus1 reports whether e divides p-1, for prime e this means gcd(e, p-1) != 1.
func dividesPMinus1(e, p *big.Int) bool {
	pm1 := new(big.Int).Sub(p, big.NewInt(1))
	return pm1.Mod(pm1, e).Sign() == 0
}

const maxGapBits = 521

func GenerateUnsafe1024BitPrimes() (p, q *big.Int) {
	e := big.NewInt(65537)

	// generate one crypto secure random prime with gcd(e, p-1) = 1
	for {
		p, _ = rand.Prime(rand.Reader, 1024)
		if !dividesPMinus1(e, p) {
			break
		}
	}

	// Fermat needs ~(q-p)^2 / (8p) iterations, so a gap below 2^521 stays under ~45k, within main.go maxIters.
	gap, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), maxGapBits-1))
	gap.Lsh(gap, 1)

	two := big.NewInt(2)
	q = new(big.Int).Add(p, gap)

	for {
		q.Add(q, two)
		if q.ProbablyPrime(20) && !dividesPMinus1(e, q) {
			return p, q
		}
	}
}
