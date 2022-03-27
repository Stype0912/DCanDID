package commitment

import (
	"math/big"
)

func Open(v, r, commitment *big.Int) bool {
	if new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(g, v, Q), new(big.Int).Exp(h, r, Q)), Q).Cmp(commitment) == 0 {
		return true
	} else {
		return false
	}
}
