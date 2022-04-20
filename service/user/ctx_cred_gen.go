package user

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"math/big"
)

type CtxProofStruct struct {
	PublicWitness *ContextCircuit
	Proof         groth16.Proof
	VerifyingKey  groth16.VerifyingKey
}

type CtxCred struct {
	PkU        string
	Ctx        string
	MasterCred *MasterCred
	Claim      *ProofStruct
	Proof      *CtxProofStruct
}

func (u *User) CtxCredIssue(cred *MasterCred) *CtxCred {
	proof := CtxCommitment(u.Id, "21")
	return &CtxCred{
		PkU:        u.PkU,
		Ctx:        "Age is over 18",
		MasterCred: cred,
		Claim:      u.Claim[0],
		Proof:      proof,
	}
}

type ContextCircuit struct {
	PreImage frontend.Variable
	Age      frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
	Limit    frontend.Variable `gnark:",public"`
	Seed     *big.Int
}

func (circuit *ContextCircuit) Define(curveID ecc.ID, api frontend.API) error {
	mimc, _ := mimc.NewMiMC(circuit.Seed.String(), curveID, api)
	mimc.Write(circuit.PreImage)
	api.AssertIsEqual(circuit.Hash, mimc.Sum())
	api.AssertIsLessOrEqual(circuit.Limit, circuit.Age)
	return nil
}

func CtxCommitment(id, age string) *CtxProofStruct {
	preImage := []byte(id)
	seed := big.NewInt(1)
	hash := mimcHash(preImage)
	var circuit ContextCircuit
	circuit.Seed = seed
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		fmt.Printf("Compile failed : %v\n", err)
		return nil
	}
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Setup failed\n")
		return nil
	}

	witness := &ContextCircuit{
		PreImage: frontend.Value(preImage),
		Age:      frontend.Value(age),
		Limit:    frontend.Value("18"),
		Hash:     frontend.Value(hash),
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("Prove failed： %v\n", err)
		return nil
	}

	publicWitness := &ContextCircuit{
		Hash:  frontend.Value(hash),
		Limit: frontend.Value("18"),
	}
	commitment := new(CtxProofStruct)
	commitment.VerifyingKey = vk
	commitment.PublicWitness = publicWitness
	commitment.Proof = proof
	//commitmentByte, _ := json.Marshal(commitment)
	//fmt.Println(string(commitmentByte))
	return commitment
}

func mimcHash(data []byte) string {
	f := bn254.NewMiMC("1")
	f.Write(data)
	hash := f.Sum(nil)
	hashInt := big.NewInt(0).SetBytes(hash)
	return hashInt.String()
}
