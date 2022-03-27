package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	_ "github.com/go-sql-driver/mysql"
	"net/http"
	"time"
)

type UserInfo struct {
	UserName string `json:"user_name"`
	PassWord string `json:"pass_word"`
}

type ResponseInfo struct {
	IsPass string `json:"is_pass"`
}

func signIn(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	decoder := json.NewDecoder(request.Body)

	var userInfo UserInfo
	var responseInfo ResponseInfo

	_ = decoder.Decode(&userInfo)

	db, err := sql.Open("mysql", "root:tang2000912@tcp(127.0.0.1:3306)/user_info?charset=utf8")
	if err != nil {
		responseInfo.IsPass = "数据库链接失败，请重试"
	}

	var user_name, password string
	_ = db.QueryRow("SELECT user_name, password FROM user_information WHERE user_name = ?", userInfo.UserName).Scan(&user_name, &password)

	if user_name == "" {
		responseInfo.IsPass = "尚未注册，请先注册"
	} else {
		if password == Encode(userInfo.PassWord) {
			responseInfo.IsPass = "校验通过"
		} else {
			responseInfo.IsPass = "密码错误"
		}
	}
	if err := json.NewEncoder(w).Encode(responseInfo); err != nil {
		panic(err)
	}
}

func signUp(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	decoder := json.NewDecoder(request.Body)

	var userInfo UserInfo
	var responseInfo ResponseInfo

	_ = decoder.Decode(&userInfo)

	db, err := sql.Open("mysql", "root:tang2000912@tcp(127.0.0.1:3306)/user_info?charset=utf8")
	if err != nil {
		responseInfo.IsPass = "数据库链接失败，请重试"
	}

	var user_name, password string
	_ = db.QueryRow("SELECT user_name, password FROM user_information WHERE user_name = ?", userInfo.UserName).Scan(&user_name, &password)
	if user_name != "" {
		responseInfo.IsPass = "已注册，请登陆"
	} else {
		_, err := db.Exec("INSERT INTO user_information (user_name, password, submission_date) VALUES (?, ?, ?)", userInfo.UserName, Encode(userInfo.PassWord), time.Now().Format("2006-01-02 15:04:05"))
		if err != nil {
			responseInfo.IsPass = "注册失败，请重试"
		} else {
			responseInfo.IsPass = "注册成功，请登陆"
		}
	}
	if err := json.NewEncoder(w).Encode(responseInfo); err != nil {
		panic(err)
	}
}

func Encode(password string) (encodedPassword string) {
	h := sha256.New()
	h.Write([]byte(password))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}
func main() {
	http.HandleFunc("/signin", signIn)
	http.HandleFunc("/signup", signUp)
	_ = http.ListenAndServe(":8090", nil)
}
