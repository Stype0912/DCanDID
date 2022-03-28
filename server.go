package main

import (
	"github.com/Stype0912/DCanDID/action"
	_ "github.com/go-sql-driver/mysql"
	"net/http"
)

func main() {
	http.HandleFunc("/signin", action.OracleGetCommit)
	http.HandleFunc("/check", action.CommitmentVerify)
	http.HandleFunc("/sign", action.SignClaim)
	_ = http.ListenAndServe(":7890", nil)
}
