package compose

import (
	"github.com/ory-am/fosite"
	"github.com/jacyzon/gorvp/handler/oauth2"
	fositeOauth2 "github.com/ory-am/fosite/handler/oauth2"
	fositeCompose "github.com/ory-am/fosite/compose"
)

// OAuth2AuthorizeImplicitRefreshFactory creates an OAuth2 implicit grant ("authorize implicit flow") handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2AuthorizeImplicitRefreshFactory(config *fositeCompose.Config, storage interface{}, strategy interface{}) interface{} {
	return &oauth2.AuthorizeImplicitRefreshGrantTypeHandler{
		AccessTokenStrategy: strategy.(fositeOauth2.AccessTokenStrategy),
		RefreshTokenStrategy: strategy.(fositeOauth2.RefreshTokenStrategy),
		AccessTokenStorage:  storage.(fositeOauth2.AccessTokenStorage),
		RefreshTokenGrantStorage:  storage.(fositeOauth2.RefreshTokenGrantStorage),
		AccessTokenLifespan: config.GetAccessTokenLifespan(),
		ScopeStrategy:       fosite.HierarchicScopeStrategy,
	}
}
