package user

import (
	"encoding/hex"
	"encoding/json"
	"github.com/Stype0912/DCanDID/util/threshold_signature"
	"k8s.io/klog"
	"math/big"
)

func (u *User) SignatureCombine(signature map[int]*big.Int) *PC {
	userInfoStr, err := json.Marshal(u)
	if err != nil {
		klog.Errorf("Marshal error: %v", err)
		return nil
	}
	userInfoNum := hex.EncodeToString(userInfoStr)
	userInfoBigNum, _ := new(big.Int).SetString(userInfoNum, 16)
	Pi := threshold_signature.Combine(userInfoBigNum, signature)
	return &PC{
		Claim: u.Claim,
		PkU:   u.PkU,
		Pi:    Pi,
	}
}
