package credential_issue

import (
	"encoding/json"
	"github.com/Stype0912/DCanDID/common"
	"github.com/Stype0912/DCanDID/handler/committee"
	"github.com/Stype0912/DCanDID/util/threshold_signature"
	"math/big"
)

type Credential struct {
	Content   *common.M `json:"content"`
	Signature string    `json:"signature"`
}

func (c *Credential) MasterCredentialIssue(pc common.PreCredential) {
	claim := pc.Claim
	m := &common.M{
		PkU:     common.Pk,
		Context: "Master",
		Claim:   claim,
	}
	m.CredentialSubject.Check = "dedupOver"
	m.CredentialSubject.Attribute = &common.Attribute{
		{
			Value:    claim.Cv.String(),
			Provider: "gov.cn",
		},
	}
	mByte, _ := json.Marshal(m)
	//mStr := string(mByte)
	sigma := committee.Sign(new(big.Int).SetBytes(mByte))
	signature := threshold_signature.Combine(new(big.Int).SetBytes(mByte), sigma)
	c.Content = m
	c.Signature = signature.String()
	return
}

func (c *Credential) MasterCredentialVerify() bool {
	mByte, _ := json.Marshal(c.Content)
	X, _ := new(big.Int).SetString(c.Signature, 10)
	return threshold_signature.Verify(new(big.Int).SetBytes(mByte), X)
}
