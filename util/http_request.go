package util

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

func DoHttpGetRequest(url string, req interface{}, resp interface{}) (err error) {
	jsonStr, _ := json.Marshal(req)
	request, err := http.NewRequest("GET", url, bytes.NewBuffer(jsonStr))
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)
	json.Unmarshal(body, resp)
	return
}
