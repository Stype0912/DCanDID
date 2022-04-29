package handler

import (
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/user"
	"github.com/Stype0912/DCanDID/service/verifier"
	"github.com/Stype0912/DCanDID/util"
	"io/ioutil"
	"k8s.io/klog"
	"net/http"
	"strings"
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
	v := &verifier.Verifier{}

	fileName := "./cred/" + userInfo.Id
	if !strings.Contains(fileName, "ctx") {
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
			masterCred := &user.MasterCred{
				Id:        cachedMasterCred.Id,
				PkU:       cachedMasterCred.PkU,
				Ctx:       cachedMasterCred.Ctx,
				Claim:     oldClaim,
				DedupOver: cachedMasterCred.DedupOver,
				Signature: cachedMasterCred.Signature,
			}
			responseInfo.IsValid = v.MasterCredVerify(masterCred)
			return
		}
	} else {
		fileContent, err := ioutil.ReadFile(fileName)
		if err == nil {
			var cachedCtxCred *user.CachedCtxCred
			err := json.Unmarshal(fileContent, &cachedCtxCred)
			if err != nil {
				klog.Errorf("Json unmarshal error: %v", err)
				return
			}
			oldMasterClaim := make([]*user.ProofStruct, 0)
			for _, item := range cachedCtxCred.MasterCred.Claim {
				proof := util.DecodeString2GrothProof(item.Proof)
				vk := util.DecodeString2GrothVK(item.VerifyingKey)
				newClaimTmp := &user.ProofStruct{
					PublicWitness: item.PublicWitness,
					Proof:         proof,
					VerifyingKey:  vk,
				}
				oldMasterClaim = append(oldMasterClaim, newClaimTmp)
			}
			masterCred := &user.MasterCred{
				Id:        cachedCtxCred.MasterCred.Id,
				PkU:       cachedCtxCred.MasterCred.PkU,
				Ctx:       cachedCtxCred.MasterCred.Ctx,
				Claim:     oldMasterClaim,
				DedupOver: cachedCtxCred.MasterCred.DedupOver,
				Signature: cachedCtxCred.MasterCred.Signature,
			}
			oldClaim := &user.ProofStruct{
				PublicWitness: cachedCtxCred.Claim.PublicWitness,
				Proof:         util.DecodeString2GrothProof(cachedCtxCred.Claim.Proof),
				VerifyingKey:  util.DecodeString2GrothVK(cachedCtxCred.Claim.VerifyingKey),
			}
			oldProof := &user.CtxProofStruct{
				PublicWitness: cachedCtxCred.Proof.PublicWitness,
				Proof:         util.DecodeString2GrothProof(cachedCtxCred.Proof.Proof),
				VerifyingKey:  util.DecodeString2GrothVK(cachedCtxCred.Proof.VerifyingKey),
			}
			ctxCred := &user.CtxCred{
				Id:         cachedCtxCred.Id,
				PkU:        cachedCtxCred.PkU,
				Ctx:        cachedCtxCred.Ctx,
				MasterCred: masterCred,
				Claim:      oldClaim,
				Proof:      oldProof,
			}
			klog.Info(masterCred)
			klog.Info(ctxCred)
			responseInfo.IsValid = v.MasterCredVerify(masterCred) && v.CtxProofVerify(ctxCred)
		}
	}

	//o := &oracle.Oracle{}
	//hash := o.ClaimGen(u.Id)
	//
	//claim := u.ClaimOpen(u.Id, hash)
	//signature := make(map[int]*big.Int)
	//c := &committee.Committee{}
	//for i := 1; i <= threshold_signature.L; i++ {
	//	c.Init(i)
	//	c.ClaimVerify(claim)
	//	signature[i] = c.SignClaim(u)
	//	//t.Log(c.SignClaim(u))
	//}
	//pc := u.PCSignatureCombine(signature)
	//
	//signature1 := make(map[int]*big.Int)
	//for i := 1; i <= threshold_signature.L; i++ {
	//	c.Init(i)
	//	signature1[i] = c.MasterCredIssue(u, pc)
	//}
	//masterCred := u.MasterCredSignatureCombine(signature1)
	//ctxCred := u.CtxCredIssue(masterCred)
	//
	//v := &verifier.Verifier{}
	//klog.Info(v.MasterCredVerify(masterCred) && v.CtxProofVerify(ctxCred))
	//responseInfo.IsValid = v.MasterCredVerify(masterCred) && v.CtxProofVerify(ctxCred)
}
