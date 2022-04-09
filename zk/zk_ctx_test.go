package zk

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

type Witness struct {
	VerifyingKey  string `json:"verifying_key"`
	PublicWitness string `json:"public_witness"`
}

func TestCtxZk(t *testing.T) {
	com := CtxCommitment("320282200009128411")
	////a, _ := json.Marshal(com.Proof)
	////b, _ := json.Marshal(com.VerifyingKey)
	//c, _ := json.Marshal(com.PublicWitness)
	////d, _ := json.Marshal(com)
	//a := bytes.NewBuffer([]byte(""))
	//b := bytes.NewBuffer([]byte(""))
	////c := bytes.NewBuffer([]byte(""))
	//com.Proof.WriteTo(a)
	//com.VerifyingKey.WriteTo(b)
	////t.Log(b.String())
	//
	//d := hex.EncodeToString(a.Bytes())
	//e, _ := hex.DecodeString(d)
	//proof := groth16.NewProof(ecc.BN254)
	//proof.ReadFrom(bytes.NewReader(bytes.NewBuffer(e).Bytes()))
	//vk := groth16.NewVerifyingKey(ecc.BN254)
	//vk.ReadFrom(bytes.NewReader(b.Bytes()))
	//var pk *ContextCircuit
	//json.Unmarshal(c, &pk)

	var err error
	a := bytes.NewBuffer([]byte(""))
	_, err = com.Proof.WriteTo(a)
	proof := hex.EncodeToString(a.Bytes())
	t.Log(proof)

	b := bytes.NewBuffer([]byte(""))
	_, err = com.VerifyingKey.WriteTo(b)
	if err != nil {
		return
	}
	verifyingKey := hex.EncodeToString(b.Bytes())

	c, err := json.Marshal(com.PublicWitness)
	publicWitness := string(c)

	var witnessStruct Witness
	witnessStruct.VerifyingKey = verifyingKey
	witnessStruct.PublicWitness = publicWitness
	witnessByte, err := json.Marshal(witnessStruct)
	witnessStr := hex.EncodeToString(witnessByte)
	t.Log(witnessStr)
	//IsTrue := CtxCommitmentVerify(commitment)
	//t.Log(IsTrue)
}
