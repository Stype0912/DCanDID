package commitment

import (
	"math/big"
	"math/rand"
	"testing"
	"time"
)

func TestCommitment(t *testing.T) {
	v, _ := new(big.Int).SetString("320282200009128411", 10)
	r := new(big.Int).Rand(rand.New(rand.NewSource(time.Now().Unix())), Q)
	commitment := Commit(v, r)
	t.Log(commitment)
	t.Log(Open(v, r, commitment))
}
