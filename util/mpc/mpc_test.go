package mpc

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

func TestMerkleTree(t *testing.T) {
	t.Log(fmt.Sprintf("%x", sha256.Sum256(big.NewInt(1).Bytes())))
	t.Log(fmt.Sprintf("%x", sha256.Sum256(big.NewInt(2).Bytes())))
	t.Log(fmt.Sprintf("%x", sha256.Sum256(big.NewInt(3).Bytes())))
	t.Log(fmt.Sprintf("%x", sha256.Sum256(big.NewInt(4).Bytes())))
	//a, _ := new(big.Int).SetString("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a", 16)
	//b, _ := new(big.Int).SetString("dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986", 16)
	//c, _ := new(big.Int).SetString("084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5", 16)
	//d, _ := new(big.Int).SetString("e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71", 16)
	//t.Log(Mpc([]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}, -1))
	//t.Log(Mpc([]*big.Int{a, big.NewInt(2), big.NewInt(3), big.NewInt(4)}, 0))
	//t.Log(Mpc([]*big.Int{big.NewInt(1), b, big.NewInt(3), big.NewInt(4)}, 1))
	//t.Log(Mpc([]*big.Int{big.NewInt(1), big.NewInt(2), c, big.NewInt(4)}, 2))
	//t.Log(Mpc([]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), d}, 3))
}
