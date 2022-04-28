package handler

import (
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/committee"
	"github.com/Stype0912/DCanDID/service/oracle"
	"github.com/Stype0912/DCanDID/service/user"
	"github.com/Stype0912/DCanDID/util"
	"github.com/Stype0912/DCanDID/util/threshold_signature"
	"io/ioutil"
	"k8s.io/klog"
	"math/big"
	"net/http"
)

func UserGetCtxCred(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	decoder := json.NewDecoder(request.Body)

	var userInfo *UserInfo
	var responseInfo *user.CtxCred

	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()

	_ = decoder.Decode(&userInfo)
	klog.Info(userInfo.Id)
	u := &user.User{}
	u.Init()
	u.Id = userInfo.Id

	fileName := "./cred/" + userInfo.Id
	fileContent, err := ioutil.ReadFile(fileName)
	if err == nil {
		var cachedMasterCred *CachedMasterCred
		err := json.Unmarshal(fileContent, &cachedMasterCred)
		if err != nil {
			klog.Errorf("Json unmarshal error: %v", err)
			return
		}
		oldClaim := make([]*user.ProofStruct, 0)
		for _, item := range cachedMasterCred.Claim {
			proof := util.DecodeString2GrothProof(item.Proof)
			vk := util.DecodeString2GrothVK(item.VerifyingKey)
			newClaimTmp := &user.ProofStruct{
				PublicWitness: item.PublicWitness,
				Proof:         proof,
				VerifyingKey:  vk,
			}
			oldClaim = append(oldClaim, newClaimTmp)
		}
		u.Claim = oldClaim
		masterCred := &user.MasterCred{
			PkU:       cachedMasterCred.PkU,
			Ctx:       cachedMasterCred.Ctx,
			Claim:     oldClaim,
			DedupOver: cachedMasterCred.DedupOver,
			Signature: cachedMasterCred.Signature,
		}
		ctxCred := u.CtxCredIssue(masterCred)
		responseInfo = ctxCred
		klog.Info("新流程")
		return
	}

	klog.Info("旧流程")
	o := &oracle.Oracle{}
	hash := o.ClaimGen(u.Id)

	claim := u.ClaimOpen(u.Id, hash)
	signature := make(map[int]*big.Int)
	c := &committee.Committee{}
	for i := 1; i <= threshold_signature.L; i++ {
		c.Init(i)
		c.ClaimVerify(claim)
		signature[i] = c.SignClaim(u)
		//t.Log(c.SignClaim(u))
	}
	pc := u.PCSignatureCombine(signature)

	signature1 := make(map[int]*big.Int)
	for i := 1; i <= threshold_signature.L; i++ {
		c.Init(i)
		signature1[i] = c.MasterCredIssue(u, pc)
	}
	masterCred := u.MasterCredSignatureCombine(signature1)
	ctxCred := u.CtxCredIssue(masterCred)
	responseInfo = ctxCred
}
