package service

import (
	"github.com/Stype0912/DCanDID/service/committee"
	"github.com/Stype0912/DCanDID/service/oracle"
	"github.com/Stype0912/DCanDID/service/user"
	_ "github.com/go-sql-driver/mysql"
	"math/big"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestMasterCred(t *testing.T) {
	var RunTime1 int64 = 0
	var RunTime2 int64 = 0
	var wg sync.WaitGroup
	//runtime.GOMAXPROCS(10)
	for j := 1; j <= 100; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startTime := time.Now()
			id := big.NewInt(rand.Int63n(1000000000000)).String()
			o := &oracle.Oracle{}
			hash := o.ClaimGen(id)
			u := &user.User{}
			u.Init()
			u.Id = id
			claim := u.ClaimOpen(id, hash)
			signature := make(map[int]*big.Int)
			c := &committee.Committee{}
			for i := 1; i <= 15; i++ {
				c.Init(i)
				c.ClaimVerify(claim)
				signature[i] = c.SignClaim(u)
				//t.Log(c.SignClaim(u))
			}
			time.Sleep(2000 * time.Millisecond)
			pc := u.PCSignatureCombine(signature)
			t.Log(pc)
			t.Log(c.PCVerify(u, pc.Pi))

			signature1 := make(map[int]*big.Int)
			for i := 1; i <= 15; i++ {
				c.Init(i)
				signature1[i] = c.MasterCredIssue(u, pc)
			}
			//time.Sleep(200 * time.Millisecond)
			masterCred := u.MasterCredSignatureCombine(signature1)
			RunTime1 += time.Since(startTime).Milliseconds()
			t.Log(masterCred)

			startTime1 := time.Now()
			ctxCred := u.CtxCredIssue(masterCred)
			RunTime2 += time.Since(startTime1).Milliseconds()
			t.Log(ctxCred)
			//v := &verifier.Verifier{}
			//t.Log(v.MasterCredVerify(masterCred))
			//t.Log(v.CtxProofVerify(ctxCred))
		}()
	}
	wg.Wait()
	t.Log(RunTime1, RunTime2)
}
