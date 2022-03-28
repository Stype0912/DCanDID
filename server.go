package main

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Stype0912/DCanDID/zk"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	_ "github.com/go-sql-driver/mysql"
	"net/http"
	"time"
)

type UserOriginInfo struct {
	Id string `json:"id"`
}

type Claim []struct {
	Attr       string `json:"attr"`
	Commitment string `json:"commitment"`
	Provider   string `json:"provider"`
}

type ClaimResp struct {
	StatusCode int64  `json:"status_code"`
	Message    string `json:"message"`
	Claim      Claim  `json:"claim"`
	Id         string `json:"id"`
	Witness    string `json:"witness"`
	IsNew      bool   `json:"is_new"`
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

	var claimStruct Claim
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
		responseInfo.Claim = Claim{
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
			fmt.Println(err)
			return
		}

	}
	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()
}

type VerifyResp struct {
	IsValid bool `json:"is_valid"`
}

func CommitmentVerify(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	decoder := json.NewDecoder(request.Body)

	var userInfo UserOriginInfo
	var responseInfo VerifyResp

	_ = decoder.Decode(&userInfo)

	db, _ := sql.Open("mysql", "root:tang2000912@tcp(127.0.0.1:3306)/user_information?charset=utf8")

	var err error
	var witness string
	var claim string
	var isClaimed bool
	_ = db.QueryRow("SELECT claim, is_claimed, witness FROM user_information WHERE user_id = ?", userInfo.Id).Scan(&claim, &isClaimed, &witness)

	var claimStruct Claim
	var witnessStruct Witness
	if isClaimed {
		// claim以序列化的结构体存储，直接unmarshal即可
		err = json.Unmarshal([]byte(claim), &claimStruct)
		e, _ := hex.DecodeString(claimStruct[0].Commitment)
		proof := groth16.NewProof(ecc.BN254)
		_, err = proof.ReadFrom(bytes.NewReader(bytes.NewBuffer(e).Bytes()))
		if err != nil {
			return
		}

		// witness以hex存储，先解密，再反序列化
		witnessByte, _ := hex.DecodeString(witness)
		err = json.Unmarshal(witnessByte, &witnessStruct)
		if err != nil {
			return
		}

		// vk以hex格式存储，先解密，再读
		vk := groth16.NewVerifyingKey(ecc.BN254)
		f, _ := hex.DecodeString(witnessStruct.VerifyingKey)
		_, err = vk.ReadFrom(bytes.NewReader(bytes.NewBuffer(f).Bytes()))
		if err != nil {
			return
		}

		// pk以序列化结构体存储，直接反序列化
		var pk *zk.Circuit
		err = json.Unmarshal([]byte(witnessStruct.PublicWitness), &pk)
		if err != nil {
			return
		}
		commitment := zk.Com{
			Proof:         proof,
			PublicWitness: pk,
			VerifyingKey:  vk,
		}
		responseInfo.IsValid = zk.CommitmentVerify(commitment)
	}
	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()
}

func main() {
	http.HandleFunc("/signin", OracleGetCommit)
	http.HandleFunc("/check", CommitmentVerify)
	_ = http.ListenAndServe(":7890", nil)
}
