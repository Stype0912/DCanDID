package handler

import (
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/committee"
	"github.com/Stype0912/DCanDID/service/user"
	"math/big"
	"net/http"
)

type SignClaimReq struct {
	Id    int                 `json:"id"`
	Claim []*user.ProofStruct `json:"claim"`
	User  *user.User          `json:"user"`
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
	if c.ClaimVerify(req.Claim) {
		resp.Signature = c.SignClaim(req.User)
	}
}
