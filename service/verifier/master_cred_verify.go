package verifier

import (
	"encoding/hex"
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/user"
	"github.com/Stype0912/DCanDID/util/threshold_signature"
	"k8s.io/klog"
	"math/big"
)

type Verifier struct {
}

func (v *Verifier) MasterCredVerify(cred *user.MasterCred) bool {
	m := struct {
		PkU       string
		Ctx       string
		Claim     []*user.ProofStruct
		DedupOver string
	}{
		PkU:       cred.PkU,
		Ctx:       "master",
		Claim:     cred.Claim,
		DedupOver: "user_id",
	}
	masterCredInfo, err := json.Marshal(m)
	if err != nil {
		klog.Errorf("Marshal error: %v", err)
		return false
	}
	masterCredInfoNum := hex.EncodeToString(masterCredInfo)
	masterCredInfoBigNum, _ := new(big.Int).SetString(masterCredInfoNum, 16)
	signature, _ := new(big.Int).SetString(cred.Signature, 10)
	return threshold_signature.Verify(masterCredInfoBigNum, signature)
}
