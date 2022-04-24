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

	http.HandleFunc("/get-commit", handler.OracleGetCommit)
	http.HandleFunc("/sign-claim", handler.SignClaim)
	_ = http.ListenAndServe(":7890", nil)
}
