package gorvp

import (
	"time"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/ory-am/fosite"
	"strings"
	"github.com/ory-am/fosite/handler/openid"
	core "github.com/ory-am/fosite/handler/oauth2"
)

type Session struct {
	ScopeSeparator string
	core.Lifespan
	*core.HMACSession
	*core.JWTSession
	*openid.DefaultSession
}

// newSession is a helper function for creating a new session
func NewSession(lifespan core.Lifespan, userID string, scopes fosite.Arguments, clientID string, connection *Connection) *Session {
	session := &Session{
		Lifespan: lifespan,
		JWTSession: &core.JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "https://api.gorvp.dev", // TODO move into config
				Subject:   userID,
				Audience:  clientID,
				ExpiresAt: time.Now().Add(time.Hour * 6), // TODO move into config
				IssuedAt:  time.Now(),
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
		},
		ScopeSeparator: " ",
	}
	session.SetScopes(scopes)
	session.SetConnection(connection)
	return session
}

func (s *Session) CopyScopeFromClaims(claims *jwt.JWTClaims) {
	s.JWTClaims.Add("sco", claims.Get("sco"))
}

func (s *Session) SetScopes(scopes fosite.Arguments) {
	s.JWTClaims.Add("sco", strings.Join(scopes, s.ScopeSeparator))
}

func (s *Session) SetConnection(connection *Connection) {
	s.JWTClaims.Add("cni", connection.ID)
}

func GrantScope(oauth2 fosite.OAuth2Provider, ar fosite.Requester) error {
	requestClient := ar.GetClient()
	clientScopes := requestClient.GetScopes()

	for _, requestScope := range ar.GetRequestedScopes() {
		if clientScopes.Has(requestScope) {
			ar.GrantScope(requestScope)
		} else {
			return ErrPermissionDenied
		}
	}
	return nil
}