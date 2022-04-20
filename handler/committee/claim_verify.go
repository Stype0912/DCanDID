package committee

import (
	"github.com/Stype0912/DCanDID/handler/user"
	"github.com/consensys/gnark/backend/groth16"
	"k8s.io/klog"
)

type Committee struct {
	id int
}

func (c *Committee) ClaimVerify(claim []*user.ProofStruct) bool {
	for _, item := range claim {
		if !c.ProofVerify(item) {
			klog.Error("Proof verify failed")
			return false
		}
	}
	return true
}

func (c *Committee) ProofVerify(claim *user.ProofStruct) bool {
	err := groth16.Verify(claim.Proof, claim.VerifyingKey, claim.PublicWitness)
	if err != nil {
		return false
	} else {
		return true
	}
}
