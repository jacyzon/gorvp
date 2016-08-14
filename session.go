package gorvp

import (
	"time"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/ory-am/fosite"
	"strings"
	"golang.org/x/net/context"
	"github.com/ory-am/fosite/compose"
	"github.com/ory-am/fosite/handler/openid"
	core "github.com/ory-am/fosite/handler/oauth2"
)

type Session struct {
	ScopeSeparator string
	*compose.Config
	*core.HMACSession
	*core.JWTSession
	*openid.DefaultSession
}

// newSession is a helper function for creating a new session
func NewSession(config *compose.Config, userID string, scopes fosite.Arguments, clientID string, connection *Connection) *Session {
	session := &Session{
		Config: config,
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

func (s *Session) GetLifespan(ctx context.Context, requester fosite.Requester, tokenType string) time.Duration {
	switch tokenType {
	case "access_token":
		// 60 day
		return 60 * 24 * time.Hour
	case "refresh_token":
		// 6 months
		return 6 * 30 * 24 * time.Hour
	case "authorization_token":
		return 10 * time.Minute
	}
	return time.Hour
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