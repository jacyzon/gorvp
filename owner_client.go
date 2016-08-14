package gorvp

import (
	"golang.org/x/net/context"
	"net/http"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pborman/uuid"
	"time"
	"github.com/ory-am/fosite/token/jwt"
	oauth2 "github.com/ory-am/fosite/handler/oauth2"
	"net/url"
	"bytes"
	"strconv"
	goauth2 "golang.org/x/oauth2"
)

type OwnerClient struct {
	JWTStrategy          *oauth2.RS256JWTStrategy
	IdentityProviderName string
	ClientID             string
	ClientSecret         string
	MandatoryScope       string
	TokenEndpoint        string
	IdentityEndpoint     string
	Token                string
	ReNewTokenDuration   time.Duration
}

func (oc *OwnerClient) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.WriteHeader(http.StatusBadRequest)
	}
	r.ParseForm()

	conf := goauth2.Config{
		ClientID:     oc.ClientID,
		ClientSecret: oc.ClientSecret,
		Scopes:       []string{oc.MandatoryScope},
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

	oc.reNewTokenIfNeeded()
	authHeader := fmt.Sprintf("Bearer %s", oc.Token)

	// request
	form := url.Values{}
	form.Add("username", username)
	form.Add("password", password)

	client := &http.Client{}
	req, err := http.NewRequest("POST", oc.IdentityEndpoint, bytes.NewBufferString(form.Encode()))
	req.Header.Add("Authorization", authHeader)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return errors.New("User not found or wrong password")
}

func (oc *OwnerClient) reNewTokenIfNeeded() {
	if oc.needRenew() {
		oc.renewToken()
	}
}

func (oc *OwnerClient) needRenew() bool {
	token, err := oc.JWTStrategy.Decode(oc.Token)
	if err != nil {
		return true
	}
	jwtClaims := jwt.JWTClaimsFromMap(token.Claims)
	if time.Now().Add(oc.ReNewTokenDuration).Before(jwtClaims.ExpiresAt) {
		return true
	}
	return false
}

func (oc *OwnerClient) renewToken() {
	// trusted token
	JWTSession := &oauth2.JWTSession{
		JWTClaims: &jwt.JWTClaims{
			JTI:       uuid.New(),
			Issuer:    "inner", // TODO router public key
			Audience:  oc.ClientID,
			Subject:   oc.IdentityProviderName,
			ExpiresAt: time.Now().Add(time.Hour * 6),
			IssuedAt:  time.Now(),
			NotBefore: time.Now(),
		},
		JWTHeader: &jwt.Headers{},
	}
	token, _, _ := oc.JWTStrategy.Generate(JWTSession.GetJWTClaims(), JWTSession.GetJWTHeader())
	oc.Token = token
}
