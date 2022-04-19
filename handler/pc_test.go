package handler

import (
	"github.com/Stype0912/DCanDID/handler/committee"
	"github.com/Stype0912/DCanDID/handler/oracle"
	"github.com/Stype0912/DCanDID/handler/user"
	_ "github.com/go-sql-driver/mysql"
	"math/big"
	"testing"
)

func TestPC(t *testing.T) {
	id := "123456790"
	o := &oracle.Oracle{}
	hash := o.ClaimGen(id)
	u := &user.User{}
	u.Init()
	claim := u.ClaimOpen(id, hash)
	signature := make(map[int]*big.Int)
	for i := 1; i <= 15; i++ {
		c := &committee.Committee{}
		c.Init(i)
		c.ClaimVerify(claim)
		signature[i] = c.SignClaim(u)
		t.Log(c.SignClaim(u))
	}
	pc := u.SignatureCombine(signature)
	t.Log(pc)
}
