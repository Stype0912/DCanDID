package zk

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"testing"
)

type Witness struct {
	VerifyingKey  string `json:"verifying_key"`
	PublicWitness string `json:"public_witness"`
}

func TestCtxZk(t *testing.T) {
	com := CtxCommitment("320282200009128411", "20")
	//a, _ := json.Marshal(com.Proof)
	//b, _ := json.Marshal(com.VerifyingKey)
	c, _ := json.Marshal(com.PublicWitness)
	//d, _ := json.Marshal(com)
	a := bytes.NewBuffer([]byte(""))
	b := bytes.NewBuffer([]byte(""))
	//c := bytes.NewBuffer([]byte(""))
	com.Proof.WriteTo(a)
	com.VerifyingKey.WriteTo(b)
	//t.Log(b.String())

	d := hex.EncodeToString(a.Bytes())
	e, _ := hex.DecodeString(d)
	proof := groth16.NewProof(ecc.BN254)
	proof.ReadFrom(bytes.NewReader(bytes.NewBuffer(e).Bytes()))
	vk := groth16.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(bytes.NewReader(b.Bytes()))
	var pk *ContextCircuit
	json.Unmarshal(c, &pk)
	commitment := CtxCom{
		Proof:         proof,
		PublicWitness: pk,
		VerifyingKey:  vk,
	}
	IsTrue := CtxCommitmentVerify(commitment)
	t.Log(IsTrue)
}
