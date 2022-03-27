package util

import (
	"math/big"
)

func PowerMod(x, n, m *big.Int) *big.Int {
	d := big.NewInt(1)
	for {
		tmp := new(big.Int)
		if n.Cmp(big.NewInt(0)) <= 0 {
			break
		}
		if tmp.Mod(n, big.NewInt(2)).Cmp(big.NewInt(1)) == 0 {
			d.Mod(d.Mul(d, x), m)
		}
		x.Mod(x.Mul(x, x), m)
		n.Rsh(n, uint(1))
	}
	return d
}
