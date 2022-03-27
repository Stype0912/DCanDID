package common

import (
	"crypto/rsa"
	"math/big"
	"math/rand"
)

var Pk *rsa.PublicKey
var Sk *rsa.PrivateKey
var V *big.Int

type Claim struct {
	A  string   `json:"a"`
	Cv *big.Int `json:"cv"`
}

type PreCredential struct {
	Claim    *Claim         `json:"Claim"`
	PkU      *rsa.PublicKey `json:"pk_u"`
	PiOracle *big.Int       `json:"pi_oracle"`
}

type Attribute []struct {
	Value    string `json:"value"`
	Provider string `json:"provider"`
}

type M struct {
	PkU               *rsa.PublicKey `json:"pk_u"`
	Context           string         `json:"context"`
	Claim             *Claim         `json:"claim"`
	CredentialSubject struct {
		Check     string     `json:"check"`
		Attribute *Attribute `json:"attribute"`
	} `json:"credential_subject"`
}

var N = int64(15)

var Lambda, B []*big.Int

var P *big.Int

func init() {
	P, _ = new(big.Int).SetString("114466057660826548352085136953911344157318943320700600451512433047942256725079", 10)
	//for {
	//	r := rand.New(rand.NewSource(time.Now().Unix()))
	//	p = new(big.Int).Rand(r, new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil))
	//	if !p.ProbablyPrime(10) {
	//		continue
	//	}
	//	break
	//}
	r := int64(0)
	for i := int64(0); i < N; i++ {
		//r := time.Now().UnixNano()
		r++
		Lambda = append(Lambda, new(big.Int).Rand(rand.New(rand.NewSource(r)), new(big.Int).Exp(big.NewInt(2), big.NewInt(512), nil)))
		B = append(B, new(big.Int).Rand(rand.New(rand.NewSource(r)), new(big.Int).Exp(big.NewInt(2), big.NewInt(512), nil)))
	}
}
