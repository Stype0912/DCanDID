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

var TestCredMap map[string]*user.MasterCred
var TestUserMap map[string]*user.User
var TestUserId []string
var loop = 10

func TestMasterCredParallel(t *testing.T) {
	TestCredMap = make(map[string]*user.MasterCred)
	TestUserMap = make(map[string]*user.User)
	TestUserId = []string{}
	var RunTime1 int64 = 0
	var wg sync.WaitGroup
	//runtime.GOMAXPROCS(10)
	for j := 1; j <= loop; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startTime := time.Now()
			id := big.NewInt(rand.Int63n(1000000000000)).String()
			TestUserId = append(TestUserId, id)
			o := &oracle.Oracle{}
			hash := o.ClaimGen(id)
			time.Sleep(200 * time.Millisecond)
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
			time.Sleep(200 * time.Millisecond)
			pc := u.PCSignatureCombine(signature)
			t.Log(pc)
			time.Sleep(200 * time.Millisecond)
			t.Log(c.PCVerify(u, pc.Pi))

			signature1 := make(map[int]*big.Int)
			for i := 1; i <= 15; i++ {
				c.Init(i)
				signature1[i] = c.MasterCredIssue(u, pc)
			}
			time.Sleep(200 * time.Millisecond)
			masterCred := u.MasterCredSignatureCombine(signature1)
			TestCredMap[u.Id] = masterCred
			TestUserMap[u.Id] = u
			RunTime1 += time.Since(startTime).Milliseconds()
			t.Log(masterCred)

			//v := &verifier.Verifier{}
			//t.Log(v.MasterCredVerify(masterCred))
			//t.Log(v.CtxProofVerify(ctxCred))
		}()
	}
	wg.Wait()
	t.Log(RunTime1)
}

func TestCtxCredParallel(t *testing.T) {
	var RunTime2 int64 = 0
	var wg sync.WaitGroup
	for _, j := range TestUserId {
		wg.Add(1)
		go func() {
			startTime1 := time.Now()
			u := TestUserMap[j]
			_ = u.CtxCredIssue(TestCredMap[j])
			RunTime2 += time.Since(startTime1).Milliseconds()
			wg.Done()
		}()
	}
	wg.Wait()
	t.Log(RunTime2)
}

func TestMasterCredOrder(t *testing.T) {
	TestCredMap = make(map[string]*user.MasterCred)
	TestUserMap = make(map[string]*user.User)
	TestUserId = []string{}
	var RunTime1 int64 = 0
	//var wg sync.WaitGroup
	//runtime.GOMAXPROCS(10)
	for j := 1; j <= loop; j++ {
		//wg.Add(1)
		//go func() {
		//	defer wg.Done()
		startTime := time.Now()
		id := big.NewInt(rand.Int63n(1000000000000)).String()
		TestUserId = append(TestUserId, id)
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
		//time.Sleep(2000 * time.Millisecond)
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
		TestCredMap[u.Id] = masterCred
		TestUserMap[u.Id] = u
		RunTime1 += time.Since(startTime).Milliseconds()
		t.Log(masterCred)

		//v := &verifier.Verifier{}
		//t.Log(v.MasterCredVerify(masterCred))
		//t.Log(v.CtxProofVerify(ctxCred))
		//}()
	}
	//wg.Wait()
	t.Log(RunTime1)
}

func TestCtxCredOrder(t *testing.T) {
	var RunTime2 int64 = 0
	//var wg sync.WaitGroup
	for _, j := range TestUserId {
		//wg.Add(1)
		//go func() {
		startTime1 := time.Now()
		u := TestUserMap[j]
		_ = u.CtxCredIssue(TestCredMap[j])
		RunTime2 += time.Since(startTime1).Milliseconds()
		//wg.Done()
		//}()
	}
	//wg.Wait()
	t.Log(RunTime2)
}
