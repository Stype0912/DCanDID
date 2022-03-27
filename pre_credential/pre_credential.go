package pre_credential

import (
	crand "crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/Stype0912/DCanDID/common"
	"github.com/Stype0912/DCanDID/util/commitment"
	"github.com/Stype0912/DCanDID/util/threshold_signature"
	"math/big"
	"math/rand"
	"time"
)

func init() {
	var err error
	common.Sk, err = rsa.GenerateKey(crand.Reader, 1024)
	if err != nil {
		fmt.Println(err)
		return
	}
	common.Pk = &common.Sk.PublicKey
}

func PreCredentialGen() common.PreCredential {
	a := "id"
	common.V, _ = new(big.Int).SetString("320282200009128411", 10)
	r := new(big.Int).Rand(rand.New(rand.NewSource(time.Now().Unix())), commitment.Q)
	Cv := commitment.Commit(common.V, r)
	claim := &common.Claim{
		A:  a,
		Cv: Cv,
	}

	PC := common.PreCredential{
		Claim:    claim,
		PkU:      common.Pk,
		PiOracle: threshold_signature.Combine(claim.Cv, threshold_signature.Sign(claim.Cv)),
	}
	return PC
	//fmt.Printf("%V", PC)
}
