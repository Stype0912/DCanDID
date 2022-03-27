package commitment

import (
	"math/big"
)

func Commit(v, r *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(g, v, Q), new(big.Int).Exp(h, r, Q)), Q)
}
