package gorvp

import (
	"net/http"
	"strings"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/ory-am/fosite/handler/oauth2"
	"fmt"
)

type JwtProxy struct {
	ScopesKey string
	Separator string
	Strategy  *oauth2.RS256JWTStrategy
	Config    *Config
	Store     *Store
}

func NewJwtProxy(store *Store, strategy *oauth2.RS256JWTStrategy, config *Config) *JwtProxy {
	return &JwtProxy{
		ScopesKey: "sco",
		Separator: " ",
		Strategy: strategy,
		Config: config,
		Store: store,
	}
}

func (jwtp *JwtProxy) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	handler, found, scopes := matchingServerOf(r.Host, r.URL.String())

	granted := false
	if found {
		// scope not defined
		if len(scopes) == 0 {
			handler.ServeHTTP(rw, r)
			return
		}

		claims, _, err := GetTokenClaimsFromBearer(jwtp.Store, r)
		if err != nil {
			WriteError(rw, err)
			return
		}

		// parse scopes
		var scopesSlice []string
		scopeString := claims.Get(jwtp.ScopesKey).(string)
		scopesSlice = strings.Split(scopeString, jwtp.Separator)

		// check grant
		for _, requestScope := range scopesSlice {
			granted = checkGrant(scopes, requestScope)
			if granted {
				token, _ := GetBearerToken(r)
				r.Header.Add("Token", token)
				addTokenClaimHeader(claims, r)
				handler.ServeHTTP(rw, r)
				return
			}
		}
		WriteError(rw, ErrClientPermission)
		return
	}
	http.NotFound(rw, r)
}

func GetBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil // no token
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", ErrTokenNotFound
	}

	return authHeaderParts[1], nil
}

func addTokenClaimHeader(claims *jwt.JWTClaims, r *http.Request) {
	claimsMap := claims.ToMap()
	for k, v := range claimsMap {
		valueString := fmt.Sprint(v)
		r.Header.Add("Token-Claims-" + k, valueString)
	}
}
