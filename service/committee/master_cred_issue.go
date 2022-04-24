package committee

import (
	"encoding/hex"
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/user"
	"github.com/Stype0912/DCanDID/util/threshold_signature"
	"k8s.io/klog"
	"math/big"
)

func (c *Committee) MasterCredIssue(u *user.User, pc *user.PC) *big.Int {
	//if !c.PCVerify(u, pc.Pi) {
	//	klog.Error("Signature illegal")
	//	return nil
	//}
	m := struct {
		PkU       string
		Ctx       string
		Claim     []*user.ProofStruct
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
	return threshold_signature.Sign(masterCredInfoBigNum, c.id)[c.id]
}
