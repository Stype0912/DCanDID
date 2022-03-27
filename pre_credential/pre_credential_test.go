package pre_credential

import (
	"encoding/json"
	"testing"
)

func TestPre(t *testing.T) {
	PC := PreCredentialGen()
	credStr, err := json.Marshal(PC)
	t.Log(string(credStr), err)
}
