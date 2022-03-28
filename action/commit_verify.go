package action

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/Stype0912/DCanDID/zk"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"net/http"
)

type VerifyResp struct {
	IsValid bool `json:"is_valid"`
}

type VerifyRequest struct {
	Claim   ClaimStruct `json:"claim"`
	Witness string      `json:"witness"`
}

func CommitmentVerify(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	var requestInfo VerifyRequest
	var responseInfo VerifyResp

	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()

	decoder := json.NewDecoder(request.Body)
	_ = decoder.Decode(&requestInfo)

	var claimStruct ClaimStruct
	var witnessStruct Witness
	var err error

	claimStruct = requestInfo.Claim
	e, _ := hex.DecodeString(claimStruct[0].Commitment)
	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(bytes.NewReader(bytes.NewBuffer(e).Bytes()))
	if err != nil {
		return
	}

	witness := requestInfo.Witness
	// witness以hex存储，先解密，再反序列化
	witnessByte, _ := hex.DecodeString(witness)
	err = json.Unmarshal(witnessByte, &witnessStruct)
	if err != nil {
		return
	}

	// vk以hex格式存储，先解密，再读
	vk := groth16.NewVerifyingKey(ecc.BN254)
	f, _ := hex.DecodeString(witnessStruct.VerifyingKey)
	_, err = vk.ReadFrom(bytes.NewReader(bytes.NewBuffer(f).Bytes()))
	if err != nil {
		return
	}

	// pk以序列化结构体存储，直接反序列化
	var pk *zk.Circuit
	err = json.Unmarshal([]byte(witnessStruct.PublicWitness), &pk)
	if err != nil {
		return
	}
	commitment := zk.Com{
		Proof:         proof,
		PublicWitness: pk,
		VerifyingKey:  vk,
	}
	responseInfo.IsValid = zk.CommitmentVerify(commitment)
	return
}