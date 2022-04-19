package threshold_signature

import (
	"github.com/Stype0912/DCanDID/util"
	"math/big"
)

func Combine(x *big.Int, X map[int]*big.Int) *big.Int {
	w := big.NewInt(1)
	for _, Si := range S {
		if Si == 0 {
			continue
		}
		//t.Log(Si)
		xi2 := new(big.Int).Exp(new(big.Int).Mul(X[Si], X[Si]), lambda[0][Si], n)
		w = new(big.Int).Mul(w, xi2)
	}
	e_hat := new(big.Int).Mul(big.NewInt(4), new(big.Int).Mul(Delta, Delta))
	_, a, b := util.GcdExpand(e_hat, e)
	//t.Log(d, e, a, e_hat, b)
	//t.Log(new(big.Int).Add(new(big.Int).Mul(a, e_hat), new(big.Int).Mul(b, e)))
	y := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(w, a, n), new(big.Int).Exp(x, b, n)), n)
	return y
}
