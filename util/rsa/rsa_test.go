package my_rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

var Pk *rsa.PublicKey
var sk *rsa.PrivateKey

func init() {
	var err error
	sk, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Println(err)
		return
	}
	Pk = &sk.PublicKey
}

func TestRSA(t *testing.T) {
	p := "123123"
	c := Encrypt(Pk, []byte(p))
	m := Decrypt(sk, c.Bytes())
	t.Log(string(m.Bytes()))
}
