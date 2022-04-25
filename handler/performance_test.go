package handler

import (
	"github.com/Stype0912/DCanDID/util"
	"math/big"
	"math/rand"
	"sync"
	"testing"
)

var loop = 100
var UserId []string

func TestMasterCredParallel(t *testing.T) {
	//t.Parallel()
	UserId = []string{}
	var wg sync.WaitGroup
	//goroutine
	ch := make(chan bool, loop)
	for j := 1; j <= loop; j++ {
		wg.Add(1)
		ch <- true
		go func() {
			defer wg.Done()
			url := "http://127.0.0.1:7890/master-cred"
			id := big.NewInt(rand.Int63n(1000000000000)).String()
			UserId = append(UserId, id)
			req := struct {
				Id string `json:"id"`
			}{
				id,
			}
			util.DoHttpPostRequest(url, req, &struct{}{})
			<-ch
		}()
	}
	wg.Wait()
	t.Log(len(UserId))
}

func TestCtxCredParallel(t *testing.T) {
	//t.Parallel()
	t.Log(len(UserId))
	url := "http://127.0.0.1:7890/ctx-cred"
	var wg sync.WaitGroup
	//goroutine
	ch := make(chan bool, loop)
	for _, id := range UserId {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			ch <- true
			//id := big.NewInt(rand.Int63n(1000000000000)).String()
			req := struct {
				Id string `json:"id"`
			}{
				id,
			}
			util.DoHttpPostRequest(url, req, &struct{}{})
			<-ch
		}(id)
	}
	wg.Wait()
}

func TestMasterCredOrder(t *testing.T) {
	//t.Parallel()
	UserId = []string{}
	url := "http://127.0.0.1:7890/master-cred"
	for j := 1; j <= loop; j++ {
		id := big.NewInt(rand.Int63n(1000000000000)).String()
		UserId = append(UserId, id)
		req := struct {
			Id string `json:"id"`
		}{
			id,
		}
		util.DoHttpPostRequest(url, req, &struct{}{})
	}
	t.Log(len(UserId))
}

func TestCtxCredOrder(t *testing.T) {
	//t.Parallel()
	t.Log(len(UserId))
	url := "http://127.0.0.1:7890/ctx-cred"
	for _, id := range UserId {
		//id := big.NewInt(rand.Int63n(1000000000000)).String()
		req := struct {
			Id string `json:"id"`
		}{
			id,
		}
		util.DoHttpPostRequest(url, req, &struct{}{})
	}
}
