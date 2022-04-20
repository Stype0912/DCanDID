package zk

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"math/big"
	"math/rand"
	"time"
)

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

type CtxCom struct {
	Proof         groth16.Proof        `json:"proof"`
	PublicWitness *ContextCircuit      `json:"public_witness"`
	VerifyingKey  groth16.VerifyingKey `json:"verifying_key"`
}

func CtxCommitment(id, age string) (commitment CtxCom) {
	preImage := []byte(id)
	seed := new(big.Int).Rand(rand.New(rand.NewSource(time.Now().UnixNano())), big.NewInt(100000000))
	hash := mimcHash(preImage, seed)
	var circuit ContextCircuit
	circuit.Seed = seed
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		fmt.Printf("Compile failed : %v\n", err)
		return
	}
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Setup failed\n")
		return
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
		return
	}

	publicWitness := &ContextCircuit{
		Hash:  frontend.Value(hash),
		Limit: frontend.Value("18"),
	}
	commitment.VerifyingKey = vk
	commitment.PublicWitness = publicWitness
	commitment.Proof = proof
	//commitmentByte, _ := json.Marshal(commitment)
	//fmt.Println(string(commitmentByte))
	return
}

func CtxCommitmentVerify(commitment CtxCom) bool {
	err := groth16.Verify(commitment.Proof, commitment.VerifyingKey, commitment.PublicWitness)
	if err != nil {
		fmt.Printf("verification failed: %v\n", err)
		return false
	}
	fmt.Printf("verification succeded\n")
	return true
}
