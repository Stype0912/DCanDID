package user

import (
	"encoding/json"
	"fmt"
	"github.com/Stype0912/DCanDID/util"
	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"io/ioutil"
	"k8s.io/klog"
	"math/big"
)

type CachedClaimStruct struct {
	PublicWitness *Circuit `json:"public_witness"`
	Proof         string   `json:"proof"`
	VerifyingKey  string   `json:"verifying_key"`
}

type CachedCtxProofStruct struct {
	PublicWitness *ContextCircuit `json:"public_witness"`
	Proof         string          `json:"proof"`
	VerifyingKey  string          `json:"verifying_key"`
}

type CtxProofStruct struct {
	PublicWitness *ContextCircuit      `json:"public_witness"`
	Proof         groth16.Proof        `json:"proof"`
	VerifyingKey  groth16.VerifyingKey `json:"verifying_key"`
}

type CtxCred struct {
	Id         string          `json:"id"`
	PkU        string          `json:"pk_u"`
	Ctx        string          `json:"ctx"`
	MasterCred *MasterCred     `json:"master_cred"`
	Claim      *ProofStruct    `json:"claim"`
	Proof      *CtxProofStruct `json:"proof"`
}

type CachedMasterCred struct {
	Id        string               `json:"id"`
	PkU       string               `json:"pk_u"`
	Ctx       string               `json:"ctx"`
	Claim     []*CachedClaimStruct `json:"claim"`
	DedupOver string               `json:"dedup_over"`
	Signature string               `json:"signature"`
}

type CachedCtxCred struct {
	Id         string                `json:"id"`
	PkU        string                `json:"pk_u"`
	Ctx        string                `json:"ctx"`
	MasterCred *CachedMasterCred     `json:"master_cred"`
	Claim      *CachedClaimStruct    `json:"claim"`
	Proof      *CachedCtxProofStruct `json:"proof"`
}

func (u *User) CtxCredIssue(cred *MasterCred) *CtxCred {
	proof := CtxCommitment(u.Id, "21")
	ctxCred := &CtxCred{
		Id:         cred.Id + "_ctx_1",
		PkU:        u.PkU,
		Ctx:        "Age is over 18",
		MasterCred: cred,
		Claim:      u.Claim[0],
		Proof:      proof,
	}

	newMasterClaim := make([]*CachedClaimStruct, 0)
	for _, item := range cred.Claim {
		proofTmp := util.EncodeGrothProof2String(item.Proof)
		vk := util.EncodeGrothVK2String(item.VerifyingKey)
		newClaimTmp := &CachedClaimStruct{
			PublicWitness: item.PublicWitness,
			Proof:         proofTmp,
			VerifyingKey:  vk,
		}
		newMasterClaim = append(newMasterClaim, newClaimTmp)
	}

	cachedMasterCred := &CachedMasterCred{
		Id:        cred.Id,
		PkU:       cred.PkU,
		Ctx:       cred.Ctx,
		Claim:     newMasterClaim,
		DedupOver: cred.DedupOver,
		Signature: cred.Signature,
	}

	cachedCtxCred := &CachedCtxCred{
		Id:         ctxCred.Id,
		PkU:        ctxCred.PkU,
		Ctx:        ctxCred.Ctx,
		MasterCred: cachedMasterCred,
		Claim: &CachedClaimStruct{
			PublicWitness: ctxCred.Claim.PublicWitness,
			Proof:         util.EncodeGrothProof2String(ctxCred.Claim.Proof),
			VerifyingKey:  util.EncodeGrothVK2String(ctxCred.Claim.VerifyingKey),
		},
		Proof: &CachedCtxProofStruct{
			PublicWitness: ctxCred.Proof.PublicWitness,
			Proof:         util.EncodeGrothProof2String(ctxCred.Proof.Proof),
			VerifyingKey:  util.EncodeGrothVK2String(ctxCred.Proof.VerifyingKey),
		},
	}
	fileName := "./cred/" + cachedCtxCred.Id
	fileContent, _ := json.Marshal(cachedCtxCred)
	if err := ioutil.WriteFile(fileName, fileContent, 0666); err != nil {
		klog.Errorf("Write file error: %v", err)
	}
	return ctxCred
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
