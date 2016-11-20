package gorvp

import (
	"time"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/ory-am/fosite"
	"strings"
	core "github.com/ory-am/fosite/handler/oauth2"
)

type Session struct {
	ScopeSeparator string
	*core.JWTSession
}

// newSession is a helper function for creating a new session
func NewSession(lifespan LifespanConf, userID string, scopes fosite.Arguments, clientID string, connection *Connection) *Session {
	session := &Session{
		JWTSession: &core.JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "https://api.gorvp.dev", // TODO move into config
				Subject:   userID,
				Audience:  clientID,
				IssuedAt:  time.Now(),
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AuthorizeCode: time.Now().Add(lifespan.AuthorizeCode * time.Second),
				fosite.AccessToken: time.Now().Add(lifespan.AccessToken * time.Second),
				fosite.RefreshToken: time.Now().Add(lifespan.RefreshToken * time.Second),
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
			return ErrClientPermission
		}
	}
	return nil
}