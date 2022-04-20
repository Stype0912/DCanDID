package verifier

import (
	"github.com/Stype0912/DCanDID/service/user"
	"github.com/consensys/gnark/backend/groth16"
)

func (v *Verifier) CtxProofVerify(ctxCred *user.CtxCred) bool {
	claim := ctxCred.Proof
	err := groth16.Verify(claim.Proof, claim.VerifyingKey, claim.PublicWitness)
	if err != nil {
		return false
	} else {
		return true
	}
}
