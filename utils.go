package main

import (
	"fmt"
	"math/big"
)

func truncated(n *big.Int) string {
	s := n.String()
	if len(s) > 10 {
		return s[:10] + "..."
	}
	return s
}

func truncatedPair(a, b *big.Int) (string, string) {
	sa, sb := a.String(), b.String()

	cp := 0
	for cp < len(sa) && cp < len(sb) && sa[cp] == sb[cp] {
		cp++
	}

	if cp < 4 {
		return truncated(a), truncated(b)
	}

	prefix := sa[:cp]
	if len(prefix) > 10 {
		prefix = prefix[:10]
	}

	suffA, suffB := sa[cp:], sb[cp:]
	if len(suffA) > 10 {
		suffA = suffA[:10] + "..."
	}
	if len(suffB) > 10 {
		suffB = suffB[:10] + "..."
	}

	return prefix + "..." + suffA, prefix + "..." + suffB
}

func printKey(p, q *big.Int) {
	diff := new(big.Int).Sub(p, q)
	diff.Abs(diff)
	ps, qs := truncatedPair(p, q)
	fmt.Printf("  p = %s (%d bits)\n", ps, p.BitLen())
	fmt.Printf("  q = %s (%d bits)\n", qs, q.BitLen())
	fmt.Printf("  |p - q| = %s (%d bits)\n", truncated(diff), diff.BitLen())
}
