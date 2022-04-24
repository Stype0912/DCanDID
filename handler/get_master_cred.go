package handler

import (
	"encoding/json"
	"github.com/Stype0912/DCanDID/service/committee"
	"github.com/Stype0912/DCanDID/service/user"
	"github.com/Stype0912/DCanDID/util"
	"k8s.io/klog"
	"math/big"
	"net/http"
)

type UserInfo struct {
	Id string `json:"id"`
}

func UserGetMasterCred(w http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		w.WriteHeader(405)
		return
	}
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

	oracleResp := &OracleResp{}
	err := util.DoHttpPostRequest("http://127.0.0.1:7890/get-commit", userInfo, &oracleResp)
	//o := &oracle.Oracle{}
	//hash := o.ClaimGen(u.Id)
	if err != nil {
		klog.Errorf("Get commit err:%v", err)
		return
	}

	claim := u.ClaimOpen(u.Id, oracleResp.Claim)
	signature := make(map[int]*big.Int)

	c := &committee.Committee{}
	for i := 1; i <= 15; i++ {
		c.Init(i)
		if c.ClaimVerify(claim) {
			signature[i] = c.SignClaim(u)
		}
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
