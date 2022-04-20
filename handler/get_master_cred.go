package handler

import (
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/committee"
	"github.com/Stype0912/DCanDID/service/oracle"
	"github.com/Stype0912/DCanDID/service/user"
	"math/big"
	"net/http"
)

type UserInfo struct {
	Id string `json:"id"`
}

func UserGetMasterCred(w http.ResponseWriter, request *http.Request) {

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	decoder := json.NewDecoder(request.Body)

	var userInfo *UserInfo
	var responseInfo *user.MasterCred

	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()

	_ = decoder.Decode(&userInfo)
	u := &user.User{}
	u.Init()
	u.Id = userInfo.Id

	o := &oracle.Oracle{}
	hash := o.ClaimGen(u.Id)

	claim := u.ClaimOpen(u.Id, hash)
	signature := make(map[int]*big.Int)
	c := &committee.Committee{}
	for i := 1; i <= 15; i++ {
		c.Init(i)
		c.ClaimVerify(claim)
		signature[i] = c.SignClaim(u)
		//t.Log(c.SignClaim(u))
	}
	pc := u.PCSignatureCombine(signature)

	signature1 := make(map[int]*big.Int)
	for i := 1; i <= 15; i++ {
		c.Init(i)
		signature1[i] = c.MasterCredIssue(u, pc)
	}
	masterCred := u.MasterCredSignatureCombine(signature1)
	responseInfo = masterCred
}
