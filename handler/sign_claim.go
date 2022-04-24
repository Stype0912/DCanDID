package handler

import (
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/committee"
	"github.com/Stype0912/DCanDID/service/user"
	"github.com/Stype0912/DCanDID/util"
	"math/big"
	"net/http"
)

type SignClaimClaimStruct struct {
	PublicWitness *user.Circuit `json:"public_witness"`
	Proof         string        `json:"proof"`
	VerifyingKey  string        `json:"verifying_key"`
}

type SignClaimUserStruct struct {
	Id    string                  `json:"id"`
	Hash  string                  `json:"hash"`
	Claim []*SignClaimClaimStruct `json:"claim"`
	PkU   string                  `json:"pk_u"`
}

type SignClaimReq struct {
	Id    int                     `json:"id"`
	Claim []*SignClaimClaimStruct `json:"claim"`
	User  *SignClaimUserStruct    `json:"user"`
}

type SignClaimResp struct {
	Signature *big.Int `json:"signature"`
}

func SignClaim(w http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	decoder := json.NewDecoder(request.Body)

	var req *SignClaimReq
	resp := &SignClaimResp{}

	defer func() {
		json.NewEncoder(w).Encode(resp)
	}()

	_ = decoder.Decode(&req)
	c := &committee.Committee{}
	c.Init(req.Id)
	oldClaim := make([]*user.ProofStruct, 0)
	for _, item := range req.Claim {
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
	if c.ClaimVerify(oldClaim) {
		resp.Signature = c.SignClaim(oldUser)
	}
}
