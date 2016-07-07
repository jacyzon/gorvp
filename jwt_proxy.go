package gorvp

import (
	"net/http"
	"github.com/ory-am/fosite/handler/core/strategy"
	"github.com/ory-am/fosite/token/jwt"
	"fmt"
	"reflect"
)

type JwtProxy struct {
	ScopesKey string
	ScopeType interface{}
	Strategy  *strategy.RS256JWTStrategy
}

func NewJwtProxy(strategy *strategy.RS256JWTStrategy) *JwtProxy {
	return &JwtProxy{
		ScopesKey: "scopes",
		ScopeType: []string{},
		Strategy: strategy,
	}
}

func (jwtp *JwtProxy) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// TODO bearer token, move into helper
	// duplicate code, see authEndpoint handler in main
	_, token, ok := r.BasicAuth()
	if !ok {
		http.Error(rw, "missing authorization header", http.StatusBadRequest)
		return
	}
	parsedToken, err := jwtp.Strategy.Decode(token)
	if err != nil {
		http.Error(rw, "token is not valid", http.StatusForbidden)
		return
	}

	// parse scopes
	jwtClaims := jwt.JWTClaimsFromMap(parsedToken.Claims)
	scopesInterface := jwtClaims.Extra[jwtp.ScopesKey]
	var scopes[]string
	if reflect.TypeOf(scopesInterface).Kind() == reflect.Slice {
		s := reflect.ValueOf(scopesInterface)
		scopes = make([]string, s.Len())
		for i := 0; i < s.Len(); i++ {
			scopes[i] = s.Index(i).Interface().(string)
		}
	} else {
		http.Error(rw, "wrong token format, try to renew token", http.StatusForbidden)
		return
	}
	fmt.Println("from jwt proxy")
	fmt.Println(scopes)

	// TODO do scope based routing

	next(rw, r)
}
