package threshold_signature

import "math/big"

func Verify(x, y *big.Int) bool {
	fai := new(big.Int).Exp(y, e, n)
	//t.Log(fai)

	x = new(big.Int).Mod(x, n)
	//t.Log(fai, x)
	if fai.Cmp(x) == 0 {
		return true
	}
	return false
}
