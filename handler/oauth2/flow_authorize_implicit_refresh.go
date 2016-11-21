package oauth2

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"fmt"

	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/oauth2"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

// AuthorizeImplicitRefreshGrantTypeHandler is a response handler for the Authorize Code grant
// using the implicit grant type and allowing the use of refresh token
type AuthorizeImplicitRefreshGrantTypeHandler struct {
	AccessTokenStrategy      oauth2.AccessTokenStrategy
	RefreshTokenStrategy     oauth2.RefreshTokenStrategy

	// ImplicitGrantStorage is used to persist session data across requests.
	AccessTokenStorage       oauth2.AccessTokenStorage
	RefreshTokenGrantStorage oauth2.RefreshTokenGrantStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan      time.Duration

	ScopeStrategy            fosite.ScopeStrategy
}

func (c *AuthorizeImplicitRefreshGrantTypeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if !ar.GetResponseTypes().Exact("token") {
		return nil
	}

	if !ar.GetClient().GetResponseTypes().Has("token") {
		return errors.Wrap(fosite.ErrInvalidGrant, "The client is not allowed to use response type token")
	}

	if !ar.GetClient().GetGrantTypes().Has("implicit") {
		return errors.Wrap(fosite.ErrInvalidGrant, "The client is not allowed to use grant type implicit")
	}

	client := ar.GetClient()
	for _, scope := range ar.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) {
			return errors.Wrap(fosite.ErrInvalidScope, fmt.Sprintf("The client is not allowed to request scope %s", scope))
		}
	}

	// there is no need to check for https, because implicit flow does not require https
	// https://tools.ietf.org/html/rfc6819#section-4.4.2

	return c.IssueImplicitAccessToken(ctx, req, ar, resp)
}

func (c *AuthorizeImplicitRefreshGrantTypeHandler) IssueImplicitAccessToken(ctx context.Context, req *http.Request, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	// Generate the code
	token, signature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, ar)
	if err != nil {
		return errors.Wrap(fosite.ErrServerError, err.Error())
	}

	var refreshToken, refreshSignature string
	if ar.GetGrantedScopes().Has("offline") {
		refreshToken, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, ar)
		if err != nil {
			return errors.Wrap(fosite.ErrServerError, err.Error())
		}
		if err := c.RefreshTokenGrantStorage.CreateRefreshTokenSession(ctx, refreshSignature, ar); err != nil {
			return errors.Wrap(fosite.ErrServerError, err.Error())
		}
	}
	if err := c.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, ar); err != nil {
		return errors.Wrap(fosite.ErrServerError, err.Error())
	}

	resp.AddFragment("access_token", token)
	resp.AddFragment("expires_in", strconv.Itoa(int(c.AccessTokenLifespan / time.Second)))
	resp.AddFragment("token_type", "bearer")
	resp.AddFragment("state", ar.GetState())
	resp.AddFragment("scope", strings.Join(ar.GetGrantedScopes(), "+"))
	if refreshToken != "" {
		resp.AddFragment("refresh_token", refreshToken)
	}
	ar.SetResponseTypeHandled("token")

	return nil
}
