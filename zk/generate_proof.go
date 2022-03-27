package main

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

type Circuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
	Seed     *big.Int
}

func (circuit *Circuit) Define(curveID ecc.ID, api frontend.API) error {
	mimc, _ := mimc.NewMiMC(circuit.Seed.String(), curveID, api)
	mimc.Write(circuit.PreImage)
	api.AssertIsEqual(circuit.Hash, mimc.Sum())
	return nil
}

func mimcHash(data []byte, seed *big.Int) string {
	f := bn254.NewMiMC(seed.String())
	f.Write(data)
	hash := f.Sum(nil)
	hashInt := big.NewInt(0).SetBytes(hash)
	return hashInt.String()
}

func main() {
	preImage := []byte{0x01, 0x02, 0x03}
	hash := mimcHash(preImage, big.NewInt(2))

	fmt.Printf("hash: %s\n", hash)

	var circuit Circuit
	circuit.Seed = big.NewInt(2)
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

	witness := &Circuit{
		PreImage: frontend.Value(preImage),
		Hash:     frontend.Value(hash),
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("Prove failed： %v\n", err)
		return
	}

	publicWitness := &Circuit{
		Hash: frontend.Value(hash),
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("verification failed: %v\n", err)
		return
	}
	fmt.Printf("verification succeded\n")
}
