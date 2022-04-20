package committee

import (
	"encoding/hex"
	"encoding/json"
	"github.com/Stype0912/DCanDID/handler/user"
	"github.com/Stype0912/DCanDID/util/threshold_signature"
	"k8s.io/klog"
	"math/big"
)

func (c *Committee) Init(id int) {
	c.id = id
}

func (c *Committee) SignClaim(userInfo *user.User) *big.Int {
	userInfoStr, err := json.Marshal(userInfo)
	if err != nil {
		klog.Errorf("Marshal error: %v", err)
		return nil
	}
	userInfoNum := hex.EncodeToString(userInfoStr)
	userInfoBigNum, _ := new(big.Int).SetString(userInfoNum, 16)
	return threshold_signature.Sign(userInfoBigNum, c.id)[c.id]
}
