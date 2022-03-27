package util

import "math/big"

func GcdExpand(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	if b.Cmp(big.NewInt(0)) == 0 {
		return a, big.NewInt(1), big.NewInt(0)
	} else {
		//tmp := new(big.Int)
		d, x1, y1 := GcdExpand(b, new(big.Int).Mod(a, b))
		tmp1 := new(big.Int).Div(a, b)
		tmp2 := new(big.Int).Mul(tmp1, y1)
		x0, y0 := y1, x1.Sub(x1, tmp2)
		return d, x0, y0
	}
}
