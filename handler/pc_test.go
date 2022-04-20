package handler

import (
	"github.com/Stype0912/DCanDID/handler/committee"
	"github.com/Stype0912/DCanDID/handler/oracle"
	"github.com/Stype0912/DCanDID/handler/user"
	"github.com/Stype0912/DCanDID/handler/verifier"
	_ "github.com/go-sql-driver/mysql"
	"math/big"
	"math/rand"
	"testing"
)

func TestPC(t *testing.T) {
	for j := 0; j <= 0; j++ {
		id := big.NewInt(rand.Int63n(1000000000000)).String()
		o := &oracle.Oracle{}
		hash := o.ClaimGen(id)
		u := &user.User{}
		u.Init()
		claim := u.ClaimOpen(id, hash)
		signature := make(map[int]*big.Int)
		c := &committee.Committee{}
		for i := 1; i <= 15; i++ {
			c.Init(i)
			c.ClaimVerify(claim)
			signature[i] = c.SignClaim(u)
			//t.Log(c.SignClaim(u))
		}
		pc := u.PCSignatureCombine(signature)
		t.Log(pc)
		t.Log(c.PCVerify(u, pc.Pi))

		signature1 := make(map[int]*big.Int)
		for i := 1; i <= 15; i++ {
			c.Init(i)
			signature1[i] = c.MasterCredIssue(u, pc)
		}
		masterCred := u.MasterCredSignatureCombine(signature1)
		t.Log(masterCred)
		ctxCred := u.CtxCredIssue(masterCred)
		v := &verifier.Verifier{}
		t.Log(v.MasterCredVerify(masterCred))
		t.Log(v.CtxProofVerify(ctxCred.Proof))
	}
}
