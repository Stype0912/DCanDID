package action

import (
	"encoding/json"
	"github.com/ing-bank/zkrp/bulletproofs"
	"k8s.io/klog"
	"math/big"
	"net/http"
)

type ContextBasedCredential struct {
}

func GenerateContextBasedCredential(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	var requestInfo MasterCredential
	var responseInfo ContextBasedCredential
	//var err error

	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()

	decoder := json.NewDecoder(request.Body)
	_ = decoder.Decode(&requestInfo)

	params, err := bulletproofs.SetupGeneric(18, 200)
	if err != nil {
		return
	}
	bigSecret := new(big.Int).SetInt64(int64(20))
	proof, _ := bulletproofs.ProveGeneric(bigSecret, params)
	klog.Info(proof)
	return
}
