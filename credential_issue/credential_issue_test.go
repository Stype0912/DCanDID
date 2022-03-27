package credential_issue

import (
	"encoding/json"
	"github.com/Stype0912/DCanDID/common"
	dedup "github.com/Stype0912/DCanDID/deduplication"
	"github.com/Stype0912/DCanDID/pre_credential"
	"testing"
)

func TestMaster(t *testing.T) {
	PC := pre_credential.PreCredentialGen()
	t.Log(PC.PiOracle, PC.Claim.Cv)
	v_hat, rawData := dedup.DeduplicationUser(common.V)
	//rawData := func() []string {
	//	return mpc.CalculateHashedLeaves(v, -1)
	//}()
	t.Log(rawData)
	for i := 0; i <= 10; i++ {
		rawData[i] = ""
		vi := dedup.DeduplicationCommitteeVi(v_hat, int64(i))
		t.Log(dedup.DeduplicationCommitteeMPC(rawData, i, vi))
	}

	credMaster := &Credential{}
	credMaster.MasterCredentialIssue(PC)
	credStr, _ := json.Marshal(credMaster)
	t.Log(string(credStr))
	//mByte, _ := json.Marshal(credMaster.Content)
	//X, _ := new(big.Int).SetString(credMaster.Signature, 10)
	//t.Log(threshold_signature.Verify(new(big.Int).SetBytes(mByte), X))
	t.Log(credMaster.MasterCredentialVerify())
}
