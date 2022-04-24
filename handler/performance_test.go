package handler

import (
	"github.com/Stype0912/DCanDID/util"
	"math/big"
	"math/rand"
	"sync"
	"testing"
)

func TestMasterCred(t *testing.T) {
	var wg sync.WaitGroup
	for j := 1; j <= 100; j++ {
		wg.Add(1)
		go func() {
			url := "http://127.0.0.1:7890/master-cred"
			id := big.NewInt(rand.Int63n(1000000000000)).String()
			req := struct {
				Id string `json:"id"`
			}{
				id,
			}
			util.DoHttpPostRequest(url, req, &struct{}{})
			wg.Done()
		}()
	}
	wg.Wait()
}
