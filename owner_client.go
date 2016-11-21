package gorvp

import (
	"golang.org/x/net/context"
	"net/http"
	"encoding/json"
	"errors"
	"bytes"
	"strconv"
	goauth2 "golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v1"
)

type OwnerClient struct {
	TokenEndpoint string
	TrustedClient *TrustedClient
}

type IdentityRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (oc *OwnerClient) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.WriteHeader(http.StatusBadRequest)
	}
	r.ParseForm()
	conf := goauth2.Config{
		ClientID:     oc.TrustedClient.ID,
		ClientSecret: oc.TrustedClient.Secret,
		Scopes:       oc.TrustedClient.Scopes.ToArguments(),
		Endpoint:     goauth2.Endpoint{TokenURL: oc.TokenEndpoint},
	}
	token, err := conf.PasswordCredentialsToken(goauth2.NoContext,
		r.PostForm.Get("username"), r.PostForm.Get("password"))
	if err != nil {
		rw.WriteHeader(http.StatusNotFound)
	}
	tokenRes, _ := json.Marshal(token)
	// TODO null json object
	rw.Header().Add("Content-Type", "application/json")
	rw.Write(tokenRes)
}

func (oc *OwnerClient) Authenticate(_ context.Context, username string, password string) error {
	// request
	ir := &IdentityRequest{
		Username: username,
		Password: password,
	}
	requestJson, _ := json.Marshal(ir)

	encrypter, err := jose.NewEncrypter(jose.DIRECT, jose.A256GCM, []byte(oc.TrustedClient.SharedKey))
	encryptedRequest, err := encrypter.Encrypt(requestJson)
	serializedRequest := encryptedRequest.FullSerialize()

	client := &http.Client{}
	req, err := http.NewRequest("POST", oc.TrustedClient.IdentityEndpoint, bytes.NewBufferString(serializedRequest))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len([]byte(serializedRequest))))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return errors.New("User not found or wrong password")
}

