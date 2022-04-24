package handler

import (
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/oracle"
	"net/http"
)

type OracleResp struct {
	Claim string `json:"claim"`
}

func OracleGetCommit(w http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	decoder := json.NewDecoder(request.Body)

	var userInfo *UserInfo
	responseInfo := &OracleResp{}

	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()

	_ = decoder.Decode(&userInfo)

	o := &oracle.Oracle{}
	responseInfo.Claim = o.ClaimGen(userInfo.Id)
}
