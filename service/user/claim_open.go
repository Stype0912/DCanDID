package user

import (
	"encoding/json"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"k8s.io/klog"
	"math/big"
)

type ProofStruct struct {
	PublicWitness *Circuit
	Proof         groth16.Proof
	VerifyingKey  groth16.VerifyingKey
}

type User struct {
	Id    string
	Hash  string
	Claim []*ProofStruct
	PkU   string
}

type PC struct {
	Claim []*ProofStruct
	PkU   string
	Pi    *big.Int
}

func (u *User) Init() {
	pubByte, _ := json.Marshal(UserPublicKey)
	u.PkU = string(pubByte)
}

func (u *User) ClaimOpen(id, hash string) []*ProofStruct {
	u.ProofGen(id, hash)
	return u.Claim
}

type Circuit struct {
	Id      frontend.Variable
	Age     frontend.Variable
	IdHash  frontend.Variable `gnark:",public"`
	AgeHash frontend.Variable `gnark:",public"`
	Seed    *big.Int
}

func (circuit *Circuit) Define(curveID ecc.ID, api frontend.API) error {
	mimcId, _ := mimc.NewMiMC(circuit.Seed.String(), curveID, api)
	mimcId.Write(circuit.Id)
	api.AssertIsEqual(circuit.IdHash, mimcId.Sum())

	mimcAge, _ := mimc.NewMiMC(circuit.Seed.String(), curveID, api)
	mimcAge.Write(circuit.Age)
	api.AssertIsEqual(circuit.AgeHash, mimcAge.Sum())
	return nil
}

func (u *User) ProofGen(id, hash string) {
	var circuit Circuit
	circuit.Seed = big.NewInt(1)
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		klog.Errorf("Compile failed: %v", err)
		return
	}
	pk, vk, err := groth16.Setup(r1cs)

	witness := &Circuit{
		Id:      TransferStringToElement([]byte(id)),
		IdHash:  TransferStringToElement(hash),
		Age:     TransferStringToElement([]byte("21")),
		AgeHash: TransferStringToElement(mimcHash([]byte("21"))),
	}

	publicWitness := &Circuit{
		IdHash:  TransferStringToElement(hash),
		AgeHash: TransferStringToElement(mimcHash([]byte("21"))),
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		klog.Errorf("Proof gen error: %v", err)
		return
	}
	claimStruct := new(ProofStruct)
	claimStruct.PublicWitness = publicWitness
	claimStruct.Proof = proof
	claimStruct.VerifyingKey = vk
	u.Claim = append(u.Claim, claimStruct)
}

func TransferStringToElement(str any) frontend.Variable {
	return frontend.Value(str)
}
