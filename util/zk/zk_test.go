package zk

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"testing"
)

func TestZk(t *testing.T) {
	com := Commitment("320282200009128411")
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
	var pk *Circuit
	json.Unmarshal(c, &pk)
	commitment := Com{
		Proof:         proof,
		PublicWitness: pk,
		VerifyingKey:  vk,
	}
	IsTrue := CommitmentVerify(commitment)
	t.Log(IsTrue)
}
