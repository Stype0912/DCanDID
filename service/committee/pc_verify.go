package committee

import (
	"encoding/hex"
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/user"
	"github.com/Stype0912/DCanDID/util/threshold_signature"
	"k8s.io/klog"
	"math/big"
)

func (c *Committee) PCVerify(userInfo *user.User, signature *big.Int) bool {
	userInfoStr, err := json.Marshal(userInfo)
	if err != nil {
		klog.Errorf("Marshal error: %v", err)
		return false
	}
	userInfoNum := hex.EncodeToString(userInfoStr)
	userInfoBigNum, _ := new(big.Int).SetString(userInfoNum, 16)
	return threshold_signature.Verify(userInfoBigNum, signature)
}
