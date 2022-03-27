package commitment

import (
	"math/big"
)

var g, h, Q *big.Int

func init() {
	//bigLengthQ := new(big.Int).Exp(big.NewInt(2), big.NewInt(160), nil)
	//for {
	//	r := rand.New(rand.NewSource(time.Now().Unix()))
	//	q = new(big.Int).Rand(r, bigLengthQ)
	//	if !q.ProbablyPrime(10) {
	//		continue
	//	}
	//	break
	//}
	//g = big.NewInt(2)
	//r := rand.New(rand.NewSource(time.Now().Unix()))
	//randInt := new(big.Int).Rand(r, q)
	//h = new(big.Int).Exp(g, randInt, q)
	//fmt.Println(g, h, q, randInt)
	g, _ = new(big.Int).SetString("2", 10)
	h, _ = new(big.Int).SetString("953815583928162949324818982889637855792436024464", 10)
	Q, _ = new(big.Int).SetString("1136209767365993296224612785270580087948908392601", 10)

	// 2 953815583928162949324818982889637855792436024464 1136209767365993296224612785270580087948908392601 348504491236317925066486939436017919503200482100
}
