package handler

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
)

func TestMasterCred(t *testing.T) {
	//url := "http://127.0.0.1:7890/master-cred"
	urlValues := url.Values{}
	urlValues.Add("id", "1234567890123")
	resp, _ := http.PostForm("http://localhost:7890/master-cred", urlValues)
	body, _ := ioutil.ReadAll(resp.Body)
	t.Log(string(body))
}
