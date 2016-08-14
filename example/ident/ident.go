package ident

import (
	"net/http"
	"github.com/ory-am/fosite/handler/oauth2"
	"github.com/jacyzon/gorvp"
)

var UserTable = map[string]string{
	"peter": "foobar",
}

type IdentityProvider struct {
	JWTStrategy *oauth2.RS256JWTStrategy
}

func (ip *IdentityProvider) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// get bearer token
	token, err := gorvp.GetBearerToken(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
	}

	// validate JWT
	_, err = ip.JWTStrategy.Validate(token)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
	}

	// check user
	r.ParseForm()
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	if username != "" && password != "" &&UserTable[username] == password {
		rw.WriteHeader(http.StatusOK)
		return
	}
	rw.WriteHeader(http.StatusNotFound)
}
