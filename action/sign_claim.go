package action

import (
	"encoding/hex"
	"encoding/json"
	"github.com/Stype0912/DCanDID/util"
	"github.com/Stype0912/DCanDID/util/threshold_signature"
	"math/big"
	"net/http"
)

type SignClaimRequest struct {
	Claim   ClaimStruct `json:"claim"`
	Witness string      `json:"witness"`
	PkU     string      `json:"pk_u"`
}

type SignClaimResp struct {
	IsValid   bool             `json:"is_valid"`
	Signature map[int]*big.Int `json:"signature"`
}

func SignClaim(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	var requestInfo SignClaimRequest
	var responseInfo SignClaimResp
	var err error

	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()

	decoder := json.NewDecoder(request.Body)
	_ = decoder.Decode(&requestInfo)

	commitVerifyReq := VerifyRequest{
		Claim:   requestInfo.Claim,
		Witness: requestInfo.Witness,
	}
	commitVerifyResq := VerifyResp{}
	err = util.DoHttpGetRequest("http://127.0.0.1:7890/check-claim", commitVerifyReq, &commitVerifyResq)
	if err != nil || !commitVerifyResq.IsValid {
		responseInfo.IsValid = false
		return
	}
	responseInfo.IsValid = true
	marshalledReq, err := json.Marshal(requestInfo)
	if err != nil {
		return
	}
	toBeSigned := hex.EncodeToString(marshalledReq)
	toBeSignedBig, _ := new(big.Int).SetString(toBeSigned, 16)
	responseInfo.Signature = threshold_signature.Sign(toBeSignedBig, 1)
	return
}
