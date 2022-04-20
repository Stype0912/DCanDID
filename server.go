package main

import (
	"github.com/Stype0912/DCanDID/handler"
	_ "github.com/go-sql-driver/mysql"
	"net/http"
)

func main() {
	http.HandleFunc("/master-cred", handler.UserGetMasterCred)
	http.HandleFunc("/ctx-cred", handler.UserGetCtxCred)
	http.HandleFunc("/verify", handler.VerifierCheckCred)
	_ = http.ListenAndServe(":7890", nil)
}
