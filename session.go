package gorvp

import (
	"time"
	"github.com/ory-am/fosite/handler/core/strategy"
	"github.com/ory-am/fosite/token/jwt"
)

type Session struct {
	User string
	*strategy.JWTSession
}

// newSession is a helper function for creating a new session
func NewSession(user string, scopes []string) *Session {
	session := &Session{
		User: user,
		JWTSession: &strategy.JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "https://api.gorvp.dev",
				Subject:   user,
				Audience:  "trusted_audience",	// TODO client id
				ExpiresAt: time.Now().Add(time.Hour * 6),
				IssuedAt:  time.Now(),
				Extra: map[string]interface{}{
					"scopes": scopes,
				},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
		},
	}
	return session
}

