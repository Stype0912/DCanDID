package action

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"k8s.io/klog"
)

var UserPublicKey *rsa.PublicKey

func init() {
	publicKey, err := ioutil.ReadFile("./action/public.pem")
	block, _ := pem.Decode(publicKey)
	if block == nil {
		klog.Error("public rsa key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		klog.Error("error")
	}
	UserPublicKey = pubInterface.(*rsa.PublicKey)
}
