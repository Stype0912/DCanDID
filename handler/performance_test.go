package handler

import (
	"github.com/Stype0912/DCanDID/service/user"
	"github.com/Stype0912/DCanDID/util"
	"math/big"
	"math/rand"
	"sync"
	"testing"
	"time"
)

var loop = 1
var UserId []string

func TestMasterCredParallel(t *testing.T) {
	//t.Parallel()
	UserId = []string{}
	var wg sync.WaitGroup
	//goroutine
	//ch := make(chan bool, loop)
	var lock sync.Mutex
	timeDuration := int64(0)
	for j := 1; j <= loop; j++ {
		wg.Add(1)
		//ch <- true
		go func() {
			defer wg.Done()
			url := "http://127.0.0.1:7890/master-cred"
			id := big.NewInt(rand.Int63n(1000000000000)).String()
			req := struct {
				Id string `json:"id"`
			}{
				id,
			}
			time1 := time.Now()
			resp := &user.MasterCred{}
			util.DoHttpPostRequest(url, req, &resp)
			lock.Lock()
			UserId = append(UserId, resp.Id)
			lock.Unlock()
			timeDuration += time.Since(time1).Milliseconds()
			t.Log(time.Since(time1).Milliseconds())
			//<-ch
		}()
	}
	wg.Wait()
	t.Log(len(UserId))
	t.Log(timeDuration / int64(len(UserId)))
}

func TestCtxCredParallel(t *testing.T) {
	//t.Parallel()
	t.Log(UserId)
	url := "http://127.0.0.1:7890/ctx-cred"
	var wg sync.WaitGroup
	timeDuration := int64(0)
	for _, id := range UserId {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			//ch <- true
			//id := big.NewInt(rand.Int63n(1000000000000)).String()
			req := struct {
				Id string `json:"id"`
			}{
				id,
			}
			time1 := time.Now()
			util.DoHttpPostRequest(url, req, &struct{}{})
			timeDuration += time.Since(time1).Milliseconds()
			t.Log(time.Since(time1).Milliseconds())
			//<-ch
		}(id)
	}
	wg.Wait()
	t.Log(timeDuration / int64(len(UserId)))
}

//func TestMasterCredOrder(t *testing.T) {
//	//t.Parallel()
//	UserId = []string{}
//	url := "http://127.0.0.1:7890/master-cred"
//	for j := 1; j <= loop; j++ {
//		id := big.NewInt(rand.Int63n(1000000000000)).String()
//		UserId = append(UserId, id)
//		req := struct {
//			Id string `json:"id"`
//		}{
//			id,
//		}
//		util.DoHttpPostRequest(url, req, &struct{}{})
//	}
//	t.Log(len(UserId))
//}
//
//func TestCtxCredOrder(t *testing.T) {
//	//t.Parallel()
//	t.Log(len(UserId))
//	url := "http://127.0.0.1:7890/ctx-cred"
//	for _, id := range UserId {
//		//id := big.NewInt(rand.Int63n(1000000000000)).String()
//		req := struct {
//			Id string `json:"id"`
//		}{
//			id,
//		}
//		util.DoHttpPostRequest(url, req, &struct{}{})
//	}
//}
