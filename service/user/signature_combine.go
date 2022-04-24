package user

import (
	"encoding/hex"
	"encoding/json"
	"github.com/Stype0912/DCanDID/util/threshold_signature"
	"k8s.io/klog"
	"math/big"
)

func (u *User) PCSignatureCombine(signature map[int]*big.Int) *PC {
	oldUser := &User{
		Id:    u.Id,
		Claim: u.Claim,
		PkU:   u.PkU,
	}
	userInfoStr, err := json.Marshal(oldUser)
	if err != nil {
		klog.Errorf("Marshal error: %v", err)
		return nil
	}
	userInfoNum := hex.EncodeToString(userInfoStr)
	userInfoBigNum, _ := new(big.Int).SetString(userInfoNum, 16)
	klog.Infof("Combine content: %v", userInfoBigNum.String()[:100])
	Pi := threshold_signature.Combine(userInfoBigNum, signature)
	return &PC{
		Claim: u.Claim,
		PkU:   u.PkU,
		Pi:    Pi,
	}
}

type MasterCred struct {
	PkU       string         `json:"pk_u"`
	Ctx       string         `json:"ctx"`
	Claim     []*ProofStruct `json:"claim"`
	DedupOver string         `json:"dedup_over"`
	Signature string         `json:"signature"`
}

func (u *User) MasterCredSignatureCombine(signature map[int]*big.Int) *MasterCred {
	m := struct {
		PkU       string
		Ctx       string
		Claim     []*ProofStruct
		DedupOver string
	}{
		PkU:       u.PkU,
		Ctx:       "master",
		Claim:     u.Claim,
		DedupOver: "user_id",
	}
	masterCredInfo, err := json.Marshal(m)
	if err != nil {
		klog.Errorf("Marshal error: %v", err)
		return nil
	}
	masterCredInfoNum := hex.EncodeToString(masterCredInfo)
	masterCredInfoBigNum, _ := new(big.Int).SetString(masterCredInfoNum, 16)
	Signature := threshold_signature.Combine(masterCredInfoBigNum, signature)
	return &MasterCred{
		PkU:       u.PkU,
		Ctx:       "master",
		Claim:     u.Claim,
		DedupOver: "user_id",
		Signature: Signature.String(),
	}
}
