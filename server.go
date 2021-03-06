package main

import (
	"github.com/Stype0912/DCanDID/handler"
	_ "github.com/go-sql-driver/mysql"
	"net/http"
	_ "net/http/pprof"
)

func main() {
	http.HandleFunc("/master-cred", handler.UserGetMasterCred)
	http.HandleFunc("/ctx-cred", handler.UserGetCtxCred)
	http.HandleFunc("/verify", handler.VerifierCheckCred)

	http.HandleFunc("/get-commit", handler.OracleGetCommit)
	http.HandleFunc("/sign-claim", handler.SignClaim)
	http.HandleFunc("/sign-cred", handler.SignMasterCred)
	_ = http.ListenAndServe(":7890", nil)
	go func() {
		http.ListenAndServe("localhost:7890", nil)
	}()
}
