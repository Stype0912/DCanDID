package util

import "math/big"

func Inverse(a, n *big.Int) *big.Int {
	d, x, _ := GcdExpand(a, n)
	if d.Cmp(big.NewInt(1)) == 0 {
		tmp1 := x.Mod(x, n)
		tmp2 := new(big.Int).Add(tmp1, n)
		return new(big.Int).Mod(tmp2, n)
	} else {
		panic("a,n须互素")
		return big.NewInt(-1)
	}
}
