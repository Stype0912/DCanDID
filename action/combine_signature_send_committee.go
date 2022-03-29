package action

import (
	"encoding/hex"
	"encoding/json"
	dedup "github.com/Stype0912/DCanDID/deduplication"
	"github.com/Stype0912/DCanDID/util"
	"github.com/Stype0912/DCanDID/util/threshold_signature"
	"k8s.io/klog"
	"math/big"
	"net/http"
)

type PreCredential struct {
	Claim ClaimStruct `json:"claim"`
	PkU   string      `json:"pk_u"`

	CombinedSignature *big.Int `json:"combined_signature"`
}

func CombineSignature(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	var requestInfo UserOriginInfo
	var responseInfo PreCredential
	var err error

	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()

	decoder := json.NewDecoder(request.Body)
	_ = decoder.Decode(&requestInfo)

	claimResp := ClaimResp{}
	klog.Info(requestInfo)
	err = util.DoHttpGetRequest("http://127.0.0.1:7890/signin", requestInfo, &claimResp)
	if err != nil {
		return
	}
	klog.Info(claimResp)

	pubByte, err := json.Marshal(UserPublicKey)
	signReq := SignClaimRequest{
		Claim:   claimResp.Claim,
		Witness: claimResp.Witness,
		PkU:     string(pubByte),
	}
	signResp := SignClaimResp{}
	klog.Info(signReq)
	err = util.DoHttpGetRequest("http://127.0.0.1:7890/sign", signReq, &signResp)
	klog.Info(signResp)

	marshalledReq, err := json.Marshal(requestInfo)
	if err != nil {
		return
	}
	toBeSigned := hex.EncodeToString(marshalledReq)
	toBeSignedBig, _ := new(big.Int).SetString(toBeSigned, 16)

	responseInfo.PkU = string(pubByte)
	responseInfo.Claim = claimResp.Claim
	responseInfo.CombinedSignature = threshold_signature.Combine(toBeSignedBig, signResp.Signature)
	return
}

type MStruct struct {
	PkU     string      `json:"pk_u"`
	Context string      `json:"context"`
	Claim   ClaimStruct `json:"claim"`
	Check   string      `json:"check"`
}

type DedupResp struct {
	M         MStruct          `json:"m"`
	Signature map[int]*big.Int `json:"signature"`
}

type DedupReq struct {
	PkU     string      `json:"pk_u"`
	VHat    *big.Int    `json:"v_hat"`
	Claim   ClaimStruct `json:"claim"`
	RawData []string    `json:"raw_data"`
	I       int64       `json:"i"`

	CombinedSignature *big.Int `json:"combined_signature"`
}

type MasterCredential struct {
	M MStruct `json:"m"`

	CombinedSignature *big.Int `json:"combined_signature"`
}

func GenerateMaster(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	var requestInfo UserOriginInfo
	var responseInfo MasterCredential
	var err error

	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()

	decoder := json.NewDecoder(request.Body)
	_ = decoder.Decode(&requestInfo)

	PC := &PreCredential{}
	err = util.DoHttpGetRequest("http://127.0.0.1:7890/send", requestInfo, &PC)
	if err != nil {
		return
	}
	v_hat, rawData := dedup.DeduplicationUser(big.NewInt(320282200009128411))
	var rawDataDeep []string
	rawDataDeep = append(rawDataDeep, rawData...)

	var dedupRespCollect []DedupResp
	for i := 0; i <= 10; i++ {
		rawDataDeep[i] = ""
		dedupReq := DedupReq{
			PkU:               PC.PkU,
			VHat:              v_hat,
			Claim:             PC.Claim,
			RawData:           rawData,
			I:                 int64(i),
			CombinedSignature: PC.CombinedSignature,
		}
		dedupResp := DedupResp{}
		err = util.DoHttpGetRequest("http://127.0.0.1:7890/dedup", dedupReq, &dedupResp)
		dedupRespCollect = append(dedupRespCollect, dedupResp)
	}
	klog.Info(rawData)
	responseInfo.M = dedupRespCollect[0].M
	marshalledReq, err := json.Marshal(responseInfo.M)
	if err != nil {
		return
	}
	toBeSigned := hex.EncodeToString(marshalledReq)
	toBeSignedBig, _ := new(big.Int).SetString(toBeSigned, 16)
	responseInfo.CombinedSignature = threshold_signature.Combine(toBeSignedBig, dedupRespCollect[0].Signature)
	return
}

func SignM(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	var requestInfo DedupReq
	var responseInfo DedupResp
	//var err error

	defer func() {
		json.NewEncoder(w).Encode(responseInfo)
	}()

	decoder := json.NewDecoder(request.Body)
	_ = decoder.Decode(&requestInfo)

	vi := dedup.DeduplicationCommitteeVi(requestInfo.VHat, requestInfo.I)
	// todo db
	klog.Info(dedup.DeduplicationCommitteeMPC(requestInfo.RawData, int(requestInfo.I), vi))
	responseInfo.M.PkU = requestInfo.PkU
	responseInfo.M.Claim = requestInfo.Claim
	responseInfo.M.Check = "dedupOver"
	marshalledReq, err := json.Marshal(responseInfo.M)
	if err != nil {
		return
	}
	toBeSigned := hex.EncodeToString(marshalledReq)
	toBeSignedBig, _ := new(big.Int).SetString(toBeSigned, 16)
	responseInfo.Signature = threshold_signature.Sign(toBeSignedBig)
	return
}
