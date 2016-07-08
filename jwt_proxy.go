package gorvp

import (
	"net/http"
	"github.com/ory-am/fosite/handler/core/strategy"
	"github.com/ory-am/fosite/token/jwt"
	"reflect"
)

type JwtProxy struct {
	ScopesKey string
	ScopeType interface{}
	Strategy  *strategy.RS256JWTStrategy
	Config    *Config
}

func NewJwtProxy(strategy *strategy.RS256JWTStrategy, config *Config) *JwtProxy {
	return &JwtProxy{
		ScopesKey: "scopes",
		ScopeType: []string{},
		Strategy: strategy,
		Config: config,
	}
}

func (jwtp *JwtProxy) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	handler, found, scopes := matchingServerOf(r.Host, r.URL.String())

	grant := false
	if found {
		// scope not defined
		if len(scopes) == 0 {
			handler.ServeHTTP(rw, r)
			return
		}

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
		var scopesJWT[]string
		if reflect.TypeOf(scopesInterface).Kind() == reflect.Slice {
			s := reflect.ValueOf(scopesInterface)
			scopesJWT = make([]string, s.Len())
			for i := 0; i < s.Len(); i++ {
				scopesJWT[i] = s.Index(i).Interface().(string)
			}
		} else {
			http.Error(rw, "wrong token format, try to renew token", http.StatusForbidden)
			return
		}

		// check grant
		for _, requestScope := range scopesJWT {
			grant = CheckGrant(scopes, requestScope)
			if grant {
				handler.ServeHTTP(rw, r)
				return
			}
		}
	} else {
		http.NotFound(rw, r)
	}

	http.Error(rw, "no permission", http.StatusForbidden)
}
