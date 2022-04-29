package handler

import (
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/user"
	"github.com/Stype0912/DCanDID/util"
	"github.com/Stype0912/DCanDID/util/threshold_signature"
	"io/ioutil"
	"k8s.io/klog"
	"math/big"
	"net/http"
)

type UserInfo struct {
	Id string `json:"id"`
}

type CachedMasterCred struct {
	Id        string                  `json:"id"`
	PkU       string                  `json:"pk_u"`
	Ctx       string                  `json:"ctx"`
	Claim     []*SignClaimClaimStruct `json:"claim"`
	DedupOver string                  `json:"dedup_over"`
	Signature string                  `json:"signature"`
}

func UserGetMasterCred(w http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	decoder := json.NewDecoder(request.Body)

	var userInfo *UserInfo
	var responseInfo *user.MasterCred

	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()

	_ = decoder.Decode(&userInfo)
	u := &user.User{}
	u.Init()
	u.Id = userInfo.Id

	oracleResp := &OracleResp{}
	err := util.DoHttpPostRequest("http://127.0.0.1:7890/get-commit", userInfo, &oracleResp)
	//o := &oracle.Oracle{}
	//hash := o.ClaimGen(u.Id)
	if err != nil {
		klog.Errorf("Get commit err:%v", err)
		return
	}

	claim := u.ClaimOpen(u.Id, oracleResp.Claim)
	signature := make(map[int]*big.Int, 0)

	//c := &committee.Committee{}
	signClaimResp := &SignClaimResp{}
	newClaim := make([]*SignClaimClaimStruct, 0)
	for _, item := range claim {
		proof := util.EncodeGrothProof2String(item.Proof)
		vk := util.EncodeGrothVK2String(item.VerifyingKey)
		newClaimTmp := &SignClaimClaimStruct{
			PublicWitness: item.PublicWitness,
			Proof:         proof,
			VerifyingKey:  vk,
		}
		newClaim = append(newClaim, newClaimTmp)
	}
	newUser := &SignClaimUserStruct{
		Id:       u.Id,
		PublicId: u.PublicId,
		Claim:    newClaim,
		PkU:      u.PkU,
	}
	for i := 1; i <= threshold_signature.L; i++ {
		err = util.DoHttpPostRequest("http://127.0.0.1:7890/sign-claim", SignClaimReq{
			Id:    i,
			Claim: newClaim,
			User:  newUser,
		}, &signClaimResp)
		signature[i], _ = new(big.Int).SetString(signClaimResp.Signature.String(), 10)
		//c.Init(i)
		//if c.ClaimVerify(claim) {
		//	signature[i] = c.SignClaim(u)
		//}
		//t.Log(c.SignClaim(u))
	}
	klog.Info(signature)
	pc := u.PCSignatureCombine(signature)
	klog.Info(pc.Pi)

	newPc := &PCStruct{
		Claim: newClaim,
		PkU:   pc.PkU,
		Pi:    pc.Pi.String(),
	}
	signature1 := make(map[int]*big.Int)
	signCredResp := &SignCredResp{}
	for i := 1; i <= threshold_signature.L; i++ {
		//c.Init(i)
		//signature1[i] = c.MasterCredIssue(u, pc)
		err = util.DoHttpPostRequest("http://127.0.0.1:7890/sign-cred", SignCredReq{
			Id:   i,
			Pc:   newPc,
			User: newUser,
		}, &signCredResp)
		signature1[i], _ = new(big.Int).SetString(signCredResp.Signature.String(), 10)
	}
	masterCred := u.MasterCredSignatureCombine(signature1)
	cachedMasterCred := &CachedMasterCred{
		Id:        masterCred.Id,
		PkU:       masterCred.PkU,
		Ctx:       masterCred.Ctx,
		Claim:     newClaim,
		DedupOver: masterCred.DedupOver,
		Signature: masterCred.Signature,
	}
	fileName := "./cred/" + cachedMasterCred.Id
	fileContent, _ := json.Marshal(cachedMasterCred)
	if err = ioutil.WriteFile(fileName, fileContent, 0666); err != nil {
		klog.Errorf("Write file error: %v", err)
	}
	responseInfo = masterCred
}
