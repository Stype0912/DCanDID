package threshold_signature

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

func TestSign(t *testing.T) {
	t.Log(p, q, p_hat, q_hat, m, n, e, d)
	//rand.Seed(time.Now().Unix())
	//t.Log(rand.Intn(2))
	//t.Log(new(big.Int).Exp(big.NewInt(0), big.NewInt(5), nil))

	//test1 := new(big.Int).Mul(Delta, f(SOut[1]))
	//test2 := func() *big.Int {
	//	res := big.NewInt(0)
	//	for _, j := range S {
	//		res = new(big.Int).Add(res, new(big.Int).Mul(lambda[SOut[1]][j], f(j)))
	//	}
	//	return res
	//}()
	//
	//if new(big.Int).Mod(test1, m).Cmp(new(big.Int).Mod(test2, m)) != 0 {
	//	t.Log(new(big.Int).Mod(test1, m))
	//	t.Log(new(big.Int).Mod(test2, m))
	//	t.FailNow()
	//}
	x, _ := new(big.Int).SetString(fmt.Sprintf("%x", sha256.Sum256([]byte("320282200009128411"))), 16)
	X := Sign(x)
	y := Combine(x, X)
	t.Log(Verify(x, y))
}
