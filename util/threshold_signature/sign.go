package threshold_signature

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

func Sign(x *big.Int) map[int]*big.Int {
	//x, _ := new(big.Int).SetString(fmt.Sprintf("%x", sha256.Sum256([]byte(M))), 16)
	//t.Log(x)

	X := make(map[int]*big.Int)
	for i := 0; i <= l; i++ {
		X[i] = new(big.Int).Exp(x, new(big.Int).Mul(new(big.Int).Mul(big.NewInt(2), Delta), s[i]), n)
		//t.Log(X[i])
	}

	x_wave := new(big.Int).Exp(x, new(big.Int).Mul(big.NewInt(4), Delta), n)
	Ln := n.BitLen()
	L1 := 128
	r := new(big.Int).Rand(rand.New(rand.NewSource(time.Now().Unix())), new(big.Int).Exp(big.NewInt(2), new(big.Int).Add(big.NewInt(int64(Ln)), big.NewInt(int64(2*L1))), n))
	v_hat := new(big.Int).Exp(v, r, n)
	x_hat := new(big.Int).Exp(x_wave, r, n)
	for i := 1; i <= l; i++ {
		vStr := v.String()
		xWaveStr := x_wave.String()
		viStr := VK[i].String()
		xi2 := new(big.Int).Mul(X[i], X[i]).String()
		vHatStr := v_hat.String()
		xHatStr := x_hat.String()
		c, _ := new(big.Int).SetString(fmt.Sprintf("%x", sha256.Sum256([]byte(vStr+xWaveStr+viStr+xi2+vHatStr+xHatStr))), 16)
		z := new(big.Int).Add(new(big.Int).Mul(s[i], c), r)
		vzvic := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(v, z, n), new(big.Int).Exp(VK[i], new(big.Int).Mul(big.NewInt(-1), c), n)), n).String()
		xzxi2c := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(x_wave, z, n), new(big.Int).Exp(X[i], new(big.Int).Mul(big.NewInt(-2), c), n)), n).String()
		cOther, _ := new(big.Int).SetString(fmt.Sprintf("%x", sha256.Sum256([]byte(vStr+xWaveStr+viStr+xi2+vzvic+xzxi2c))), 16)
		if c.Cmp(cOther) != 0 {
			//t.Log(c, cOther)
			//t.FailNow()
			fmt.Printf("error,%v,%v", c, cOther)
		}
	}
	return X
}
