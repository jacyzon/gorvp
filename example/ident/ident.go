package ident

import (
	"net/http"
	"gopkg.in/square/go-jose.v1"
	"io/ioutil"
	"encoding/json"
	"github.com/jacyzon/gorvp"
)

var UserTable = map[string]string{
	"peter": "foobar",
}

type IdentityProvider struct {
	SharedSecret []byte
}

func (ip *IdentityProvider) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	body, _ := ioutil.ReadAll(r.Body)
	encryption, err := jose.ParseEncrypted(string(body))
	if checkErr(rw, err) {
		return
	}
	decrypted, err := encryption.Decrypt(ip.SharedSecret)
	if checkErr(rw, err) {
		return
	}
	ir := &gorvp.IdentityRequest{}
	err = json.Unmarshal(decrypted, ir)
	if checkErr(rw, err) {
		return
	}
	if ir.Username != "" && ir.Password != "" &&UserTable[ir.Username] == ir.Password {
		rw.WriteHeader(http.StatusOK)
		return
	}
	rw.WriteHeader(http.StatusNotFound)
}

func checkErr(rw http.ResponseWriter, err error) (bool) {
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		return true
	}
	return false
}
