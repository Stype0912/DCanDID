package dedup

import (
	"github.com/Stype0912/DCanDID/common"
	"github.com/Stype0912/DCanDID/util"
	"github.com/Stype0912/DCanDID/util/mpc"
	"k8s.io/klog"
	"math/big"
)

var b = common.B
var lambda = common.Lambda
var N = common.N
var p = common.P

func DeduplicationUser(vReal *big.Int) (*big.Int, []string) {
	var v []*big.Int
	//fmt.Println(new(big.Int).Mod(v, p))
	bSum := big.NewInt(0)
	for i, _ := range b {
		bSum = new(big.Int).Add(bSum, new(big.Int).Mul(lambda[i], b[i]))
	}
	v_hat := new(big.Int).Add(bSum, vReal)
	klog.Info(v_hat.String())
	for i := int64(0); i < N; i++ {
		tmp1 := new(big.Int).Mul(big.NewInt(N), lambda[i])
		tmp2 := util.Inverse(new(big.Int).Mod(tmp1, p), p)
		tmp3 := new(big.Int).Mul(v_hat, tmp2)
		v = append(v, new(big.Int).Sub(tmp3, b[i]))
	}
	rawData := mpc.CalculateHashedLeaves(v, -1)
	return v_hat, rawData
}

func DeduplicationCommitteeVi(v_hat *big.Int, i int64) *big.Int {
	//var v []*big.Int
	//for i := int64(0); i < N; i++ {
	tmp1 := new(big.Int).Mul(big.NewInt(N), lambda[i])
	tmp2 := util.Inverse(new(big.Int).Mod(tmp1, p), p)
	tmp3 := new(big.Int).Mul(v_hat, tmp2)
	//v = append(v, new(big.Int).Sub(tmp3, b[i]))
	//}
	//vSum := big.NewInt(0)
	//for i, _ := range v {
	//	vSum = new(big.Int).Add(vSum, new(big.Int).Mul(lambda[i], v[i]))
	//	vSum = new(big.Int).Mod(vSum, p)
	//}
	//fmt.Println(vSum)
	return new(big.Int).Sub(tmp3, b[i])
}

func DeduplicationCommitteeMPC(data []string, i int, vi *big.Int) string {
	v_wave := mpc.Mpc(data, i, vi)
	return v_wave
}
