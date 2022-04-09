package main

import (
	"github.com/Stype0912/DCanDID/action"
	_ "github.com/go-sql-driver/mysql"
	"net/http"
)

func main() {
	http.HandleFunc("/signin", action.OracleGetCommit)
	http.HandleFunc("/check-claim", action.CommitmentVerify)
	http.HandleFunc("/sign", action.SignClaim)
	http.HandleFunc("/send", action.CombineSignature)
	http.HandleFunc("/generate-master", action.GenerateMaster)
	http.HandleFunc("/dedup", action.SignM)
	http.HandleFunc("/commit-sign-verify", action.CommitSignVerify)
	_ = http.ListenAndServe(":7890", nil)
}
