package my_rsa

import (
	"crypto/rsa"
	"math/big"
)

func Encrypt(pk *rsa.PublicKey, plainText []byte) *big.Int {
	plain := new(big.Int).SetBytes(plainText)
	return new(big.Int).Exp(plain, big.NewInt(int64(pk.E)), pk.N)
}

func Decrypt(sk *rsa.PrivateKey, cipherText []byte) *big.Int {
	cipher := new(big.Int).SetBytes(cipherText)
	return new(big.Int).Exp(cipher, sk.D, sk.N)
}
