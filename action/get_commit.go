package action

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"github.com/Stype0912/DCanDID/zk"
	"k8s.io/klog"
	"net/http"
	"time"
)

type UserOriginInfo struct {
	Id string `json:"id"`
}

type ClaimStruct []struct {
	Attr       string `json:"attr"`
	Commitment string `json:"commitment"`
	Provider   string `json:"provider"`
}

type ClaimResp struct {
	StatusCode int64       `json:"status_code"`
	Message    string      `json:"message"`
	Claim      ClaimStruct `json:"claim"`
	Id         string      `json:"id"`
	Witness    string      `json:"witness"`
	IsNew      bool        `json:"is_new"`
}

type Witness struct {
	VerifyingKey  string `json:"verifying_key"`
	PublicWitness string `json:"public_witness"`
}

func OracleGetCommit(w http.ResponseWriter, request *http.Request) {

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	decoder := json.NewDecoder(request.Body)

	var userInfo UserOriginInfo
	var responseInfo ClaimResp

	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()

	_ = decoder.Decode(&userInfo)

	db, err := sql.Open("mysql", "root:tang2000912@tcp(127.0.0.1:3306)/user_information?charset=utf8")
	if err != nil {
		responseInfo.StatusCode = 1
		responseInfo.Message = "数据库连接失败，请重试"
	}

	var witness string
	var claim string
	var isClaimed bool
	_ = db.QueryRow("SELECT claim, is_claimed, witness FROM user_information WHERE user_id = ?", userInfo.Id).Scan(&claim, &isClaimed, &witness)

	var claimStruct ClaimStruct
	var witnessStruct Witness
	if isClaimed {
		err = json.Unmarshal([]byte(claim), &claimStruct)
		responseInfo.Claim = claimStruct
		responseInfo.Id = userInfo.Id
		responseInfo.Witness = witness
		responseInfo.IsNew = false
	} else {
		com := zk.Commitment(userInfo.Id)

		a := bytes.NewBuffer([]byte(""))
		_, err = com.Proof.WriteTo(a)
		if err != nil {
			return
		}
		proof := hex.EncodeToString(a.Bytes())

		b := bytes.NewBuffer([]byte(""))
		_, err = com.VerifyingKey.WriteTo(b)
		if err != nil {
			return
		}
		verifyingKey := hex.EncodeToString(b.Bytes())

		c, err := json.Marshal(com.PublicWitness)
		publicWitness := string(c)

		if err != nil {
			responseInfo.StatusCode = 1
			responseInfo.Message = "marshal错误，请重试"
			return
		}
		witnessStruct.VerifyingKey = verifyingKey
		witnessStruct.PublicWitness = publicWitness
		witnessByte, err := json.Marshal(witnessStruct)
		witnessStr := hex.EncodeToString(witnessByte)
		if err != nil {
			responseInfo.StatusCode = 1
			responseInfo.Message = "marshal错误，请重试"
			return
		}

		responseInfo.Id = userInfo.Id
		responseInfo.Claim = ClaimStruct{
			{
				Attr:       "id",
				Commitment: proof,
				Provider:   "gov.cn",
			},
		}
		responseInfo.IsNew = true
		responseInfo.Witness = witnessStr
		claimStr, _ := json.Marshal(responseInfo.Claim)
		_, err = db.Exec("INSERT INTO user_information (user_id, claim, is_claimed, witness, submission_date) VALUES (?, ?, ?, ?, ?)",
			userInfo.Id, claimStr, true, witnessStr, time.Now().Format("2006-01-02 15:04:05"))
		if err != nil {
			klog.Error(err)
			return
		}

	}
}
