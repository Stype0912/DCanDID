package handler

import (
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/committee"
	"github.com/Stype0912/DCanDID/service/user"
	"github.com/Stype0912/DCanDID/util"
	"math/big"
	"net/http"
)

type SignCredReq struct {
	Id   int                  `json:"id"`
	Pc   *PCStruct            `json:"pc"`
	User *SignClaimUserStruct `json:"user"`
}

type SignCredResp struct {
	Signature *big.Int `json:"signature"`
}

type PCStruct struct {
	Claim []*SignClaimClaimStruct `json:"claim"`
	PkU   string                  `json:"pk_u"`
	Pi    *big.Int                `json:"pi"`
}

func SignMasterCred(w http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	decoder := json.NewDecoder(request.Body)

	var req *SignCredReq
	resp := &SignCredResp{}

	defer func() {
		json.NewEncoder(w).Encode(resp)
	}()

	_ = decoder.Decode(&req)
	c := committee.Committee{}
	c.Init(req.Id)
	oldClaim := make([]*user.ProofStruct, 0)
	for _, item := range req.User.Claim {
		proof := util.DecodeString2GrothProof(item.Proof)
		vk := util.DecodeString2GrothVK(item.VerifyingKey)
		newClaimTmp := &user.ProofStruct{
			PublicWitness: item.PublicWitness,
			Proof:         proof,
			VerifyingKey:  vk,
		}
		oldClaim = append(oldClaim, newClaimTmp)
	}
	oldUser := &user.User{
		Id: req.User.Id,
		//Hash:  req.User.Hash,
		Claim: oldClaim,
		PkU:   req.User.PkU,
	}
	oldPc := &user.PC{
		Claim: oldClaim,
		PkU:   req.Pc.PkU,
		Pi:    req.Pc.Pi,
	}
	resp.Signature = c.MasterCredIssue(oldUser, oldPc)
}
