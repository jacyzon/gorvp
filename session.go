package gorvp

import (
	"time"
	"github.com/ory-am/fosite/handler/core/strategy"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/ory-am/fosite"
	"errors"
	"github.com/pborman/uuid"
)

type Session struct {
	*strategy.JWTSession
}

// newSession is a helper function for creating a new session
func NewSession(userID string, scopes fosite.Arguments, clientID string) *Session {
	session := &Session{
		JWTSession: &strategy.JWTSession{
			JWTClaims: &jwt.JWTClaims{
				JTI:       uuid.New(),
				Issuer:    "https://api.gorvp.dev",
				Subject:   userID,
				Audience:  clientID,
				ExpiresAt: time.Now().Add(time.Hour * 6),
				IssuedAt:  time.Now(),
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
		},
	}
	SetScopesInJWT(scopes, session)
	return session
}

func SetScopesInJWT(scopes fosite.Arguments, session *Session) {
	session.JWTClaims.Extra = map[string]interface{}{
		"scopes": scopes,
	}
}

func GrantScope(oauth2 fosite.OAuth2Provider, ar fosite.Requester) error {
	requestClient := ar.GetClient().(Client)
	clientScopes := requestClient.GetGrantedScopes()

	for _, requestScope := range ar.GetScopes() {
		if requestScope == oauth2.GetMandatoryScope() {
			// every client has permission on mandatory scope by default
			// which is set in access request handler
			continue
		}
		if clientScopes.Grant(requestScope) {
			ar.GrantScope(requestScope)
		} else {
			return errors.New("client has no permission on requested scopes")
		}
	}
	return nil
}