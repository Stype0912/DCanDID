package handler

import (
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/committee"
	"github.com/Stype0912/DCanDID/service/oracle"
	"github.com/Stype0912/DCanDID/service/user"
	"github.com/Stype0912/DCanDID/service/verifier"
	"k8s.io/klog"
	"math/big"
	"net/http"
)

type CheckResp struct {
	IsValid bool `json:"is_valid"`
}

func VerifierCheckCred(w http.ResponseWriter, request *http.Request) {

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	decoder := json.NewDecoder(request.Body)

	var userInfo *UserInfo
	responseInfo := &CheckResp{}

	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()

	_ = decoder.Decode(&userInfo)
	u := &user.User{}
	u.Init()
	u.Id = userInfo.Id

	o := &oracle.Oracle{}
	hash := o.ClaimGen(u.Id)

	claim := u.ClaimOpen(u.Id, hash)
	signature := make(map[int]*big.Int)
	c := &committee.Committee{}
	for i := 1; i <= 15; i++ {
		c.Init(i)
		c.ClaimVerify(claim)
		signature[i] = c.SignClaim(u)
		//t.Log(c.SignClaim(u))
	}
	pc := u.PCSignatureCombine(signature)

	signature1 := make(map[int]*big.Int)
	for i := 1; i <= 15; i++ {
		c.Init(i)
		signature1[i] = c.MasterCredIssue(u, pc)
	}
	masterCred := u.MasterCredSignatureCombine(signature1)
	ctxCred := u.CtxCredIssue(masterCred)

	v := &verifier.Verifier{}
	klog.Info(v.MasterCredVerify(masterCred) && v.CtxProofVerify(ctxCred))
	responseInfo.IsValid = v.MasterCredVerify(masterCred) && v.CtxProofVerify(ctxCred)
}
