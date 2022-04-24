package util

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

func DoHttpPostRequest(url string, req interface{}, resp interface{}) (err error) {
	jsonStr, _ := json.Marshal(req)
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)
	err = json.Unmarshal(body, resp)
	return
}
