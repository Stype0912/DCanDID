package util

import (
	"bytes"
	"encoding/hex"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
)

func EncodeGrothProof2String(proof groth16.Proof) string {
	a := bytes.NewBuffer([]byte(""))
	proof.WriteTo(a)
	return hex.EncodeToString(a.Bytes())
}

func DecodeString2GrothProof(proofStr string) groth16.Proof {
	a, err := hex.DecodeString(proofStr)
	if err != nil {
		return nil
	}
	proof := groth16.NewProof(ecc.BN254)
	proof.ReadFrom(bytes.NewReader(bytes.NewBuffer(a).Bytes()))
	return proof
}

func EncodeGrothVK2String(proof groth16.VerifyingKey) string {
	a := bytes.NewBuffer([]byte(""))
	proof.WriteTo(a)
	return hex.EncodeToString(a.Bytes())
}

func DecodeString2GrothVK(proofStr string) groth16.VerifyingKey {
	a, err := hex.DecodeString(proofStr)
	if err != nil {
		return nil
	}
	proof := groth16.NewVerifyingKey(ecc.BN254)
	proof.ReadFrom(bytes.NewReader(bytes.NewBuffer(a).Bytes()))
	return proof
}
