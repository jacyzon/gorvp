package gorvp

import (
	"fmt"
	"time"
	"os"
	"io/ioutil"
	"strconv"
	"net/http"
	"github.com/jinzhu/gorm"
	"github.com/ory-am/fosite/compose"
	customCompose "github.com/jacyzon/gorvp/compose"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/ory-am/fosite/handler/oauth2"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
	"github.com/pilu/xrequestid"
	"github.com/ory-am/fosite"
	"github.com/go-errors/errors"
	"strings"
)

// TODO move into gorvp struct
var tokenStrategy = &GoRvpStrategy{init: false}

type GoRvpStrategy struct {
	*oauth2.RS256JWTStrategy
	init bool
}

func SetTokenStrategy(s *oauth2.RS256JWTStrategy) {
	tokenStrategy.RS256JWTStrategy = s
	tokenStrategy.init = true
}

func GetTokenStrategy() (*GoRvpStrategy) {
	if tokenStrategy.init == false {
		// TODO init strategy for one-time use
		panic("Token strategy must set first")
	}
	return tokenStrategy
}

type GoRvp struct {
	Config       *Config
	Router       *mux.Router
	store        *Store
	oauth2       fosite.OAuth2Provider
	fositeConfig *compose.Config
}

func (goRvp *GoRvp) Run() (error) {
	err := goRvp.Config.Load()
	if (err != nil) {
		return err;
	}
	goRvp.fositeConfig = &compose.Config{
		AccessTokenLifespan: goRvp.Config.Lifespan.AccessToken * time.Second,
		AuthorizeCodeLifespan: goRvp.Config.Lifespan.AuthorizeCode * time.Second,
	}

	tokenStrategy := &oauth2.RS256JWTStrategy{
		RS256JWTStrategy: &jwt.RS256JWTStrategy{
			PrivateKey: goRvp.Config.RsaKey.Token.Key,
		},
	}

	SetupSites(goRvp.Config)
	SetTokenStrategy(tokenStrategy)

	db, err := gorm.Open(goRvp.Config.Database.Type, goRvp.Config.Database.Connection)
	if err != nil {
		return errors.New("Cannot open database.")
	}

	goRvp.store = &Store{
		DB: db,
	}
	goRvp.store.Migrate()
	goRvp.store.CreateScopeInfo(goRvp.Config)

	goRvp.oauth2 = compose.Compose(
		goRvp.fositeConfig,
		goRvp.store,
		&compose.CommonStrategy{
			// alternatively you could use OAuth2Strategy: compose.NewOAuth2JWTStrategy(mustRSAKey())
			CoreStrategy: tokenStrategy,
		},
		// enabled handlers
		compose.OAuth2AuthorizeExplicitFactory,
		customCompose.OAuth2AuthorizeImplicitRefreshFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2ResourceOwnerPasswordCredentialsFactory,
	)
	OAuth2TokenEndpoint := fmt.Sprintf("http://127.0.0.1:%s%s", goRvp.Config.Port, goRvp.Config.Oauth2TokenMountPoint)

	for _, trustedClient := range goRvp.Config.TrustedClients {
		goRvp.store.CreateTrustedClient(&trustedClient)
		oc := &OwnerClient{
			TokenEndpoint:      OAuth2TokenEndpoint,
			TrustedClient:      &trustedClient,
		}
		goRvp.Router.PathPrefix(trustedClient.TokenMountPoint).Handler(negroni.New(
			// TODO add limit plugin
			negroni.Wrap(oc),
		))
		if goRvp.store.OC == nil && trustedClient.Default_provider {
			goRvp.store.OC = oc
		}
	}

	goRvp.Router.HandleFunc(goRvp.Config.Oauth2AuthMountPoint, goRvp.authEndpoint)
	goRvp.Router.HandleFunc(goRvp.Config.Oauth2TokenMountPoint, goRvp.tokenEndpoint)

	// TODO plugins support
	jwtProxy := NewJwtProxy(goRvp.store, tokenStrategy, goRvp.Config)
	m := negroni.New(jwtProxy)
	goRvp.Config.SetupRoute(goRvp.Router, m)

	// admin API
	adminHandler := AdminHandler{
		Router:goRvp.Router.PathPrefix("/admin").Subrouter(),
		Store: goRvp.store,
	}
	adminHandler.SetupHandler()

	clientHandler := ClientHandler{
		Router:goRvp.Router.PathPrefix("/client").Subrouter(),
		Store: goRvp.store,
	}
	clientHandler.SetupHandler()

	tokenHandler := TokenHandler{
		Router:goRvp.Router.PathPrefix(goRvp.Config.Oauth2TokenMountPoint).Subrouter(),
		Store: goRvp.store,
		Hasher: goRvp.oauth2.(*fosite.Fosite).Hasher,
	}
	tokenHandler.SetupHandler()

	connectionHandler := ConnectionHandler{
		Router:goRvp.Router.PathPrefix("/connections").Subrouter(),
		Store: goRvp.store,
	}
	connectionHandler.SetupHandler()

	// attach basic middleware
	n := negroni.New(negroni.NewRecovery(), negroni.NewLogger(), xrequestid.New(16), negroni.Wrap(goRvp.Router))
	goRvp.Config.WritePidFile()
	n.Run(":" + goRvp.Config.Port)
	return nil
}

func (c *Config) WritePidFile() {
	if c.PidFile == "" {
		return
	}
	pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
	ioutil.WriteFile(c.PidFile, pid, 0644)
}

func (goRvp *GoRvp) authEndpoint(rw http.ResponseWriter, req *http.Request) {
	jwtClaims, _, err := GetTokenClaimsFromBearer(goRvp.store, req)
	if err != nil {
		WriteError(rw, err)
		return
	}

	// This context will be passed to all methods.
	ctx := fosite.NewContext()

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	req.ParseForm()
	ar, err := goRvp.oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		goRvp.oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	// check if the token is from trusted client
	authTokenClient, err := goRvp.store.GetRvpClient(jwtClaims.Audience)
	if err != nil {
		WriteError(rw, ErrTokenInvalid)
		return
	}
	authTokenRVPClient := authTokenClient
	if !authTokenRVPClient.IsTrusted() {
		WriteError(rw, ErrInvalidClient)
		return
	}

	// check scopes
	err = GrantScope(goRvp.oauth2, ar)
	if err != nil {
		WriteError(rw, ErrClientPermission)
		return
	}
	requestClient := ar.GetClient().(Client)
	clientID := requestClient.GetID()
	grantedScopes := ar.GetGrantedScopes()

	connection, err := goRvp.store.UpdateConnection(clientID, jwtClaims.Subject, grantedScopes)
	if err != nil {
		WriteError(rw, fosite.ErrServerError)
		return
	}

	// Now that the user is authorized, we set up a session:
	session := NewSession(goRvp.Config, jwtClaims.Subject, grantedScopes, requestClient.GetID(), connection)

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	response, err := goRvp.oauth2.NewAuthorizeResponse(ctx, req, ar, session)
	if err != nil {
		goRvp.oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	// check app type and relevant check
	validClient := true
	switch requestClient.GetAppType() {
	case AppTypeAndroid:
		if requestClient.GetPackageName() != ar.GetRequestForm().Get("package_name") {
			validClient = false
		} else if requestClient.GetKeyHash() != strings.ToLower(ar.GetRequestForm().Get("key_hash")) {
			validClient = false
		}
		if validClient {
			response.AddFragment("start_activity", requestClient.GetStartActivity())
		} else {
			WriteError(rw, ErrInvalidClient)
			return
		}
	}

	// Last but not least, send the response!
	goRvp.oauth2.WriteAuthorizeResponse(rw, ar, response)
}

func (goRvp *GoRvp)tokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := fosite.NewContext()

	// Create an empty session object which will be passed to the request handlers
	session := NewSession(goRvp.Config, "", []string{}, "", &Connection{})

	req.ParseForm()
	grantType := req.PostForm.Get("grant_type")
	if grantType == "refresh_token" {
		_, _, ok := req.BasicAuth()
		if !ok {
			// the client id does not found in basic auth, use client id in jwt instead
			// this is for implicit refresh flow for public client like android and web app
			claims, _, err := GetTokenClaimsFromRefreshToken(goRvp.store, req)
			if err != nil {
				WriteError(rw, err)
				return
			}
			req.SetBasicAuth(claims.Audience, "")
		}
	}

	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	ar, err := goRvp.oauth2.NewAccessRequest(ctx, req, session)

	if err != nil {
		goRvp.oauth2.WriteAccessError(rw, ar, err)
		return
	}

	// TODO refactoring: select app type
	if ar.GetGrantTypes().Exact("password") {
		client := ar.GetClient().(Client)
		clientID := client.GetID()
		if !client.GetFullScopes().Grant(ar) {
			WriteError(rw, ErrClientPermission)
			return
		}
		username := req.PostForm.Get("username")
		connection, err := goRvp.store.UpdateConnection(clientID, username, ar.GetGrantedScopes())
		if err != nil {
			WriteError(rw, err)
			return
		}
		session.SetScopes(ar.GetGrantedScopes())
		session.JWTClaims.Audience = clientID
		session.JWTClaims.Subject = username
		session.SetConnection(connection)
	} else if ar.GetGrantTypes().Exact("authorization_code") {
		claims, connection, err := GetTokenClaimsFromCode(goRvp.store, req)
		if err != nil {
			WriteError(rw, err)
			return
		}
		session.CopyScopeFromClaims(claims)
		session.JWTClaims.Audience = claims.Audience
		session.JWTClaims.Subject = claims.Subject
		session.SetConnection(connection)
	} else if ar.GetGrantTypes().Exact("client_credentials") {
		client := ar.GetClient().(Client)
		clientID := client.GetID()
		if !client.GetFullScopes().Grant(ar) {
			WriteError(rw, ErrClientPermission)
			return
		}
		session.SetScopes(ar.GetGrantedScopes())
		session.JWTClaims.Audience = clientID
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := goRvp.oauth2.NewAccessResponse(ctx, req, ar)
	if err != nil {
		goRvp.oauth2.WriteAccessError(rw, ar, err)
		return
	}

	// All done, send the response.
	goRvp.oauth2.WriteAccessResponse(rw, ar, response)

	// The client now has a valid access token
}

// TODO read in RS key
// TODO http method based scope
// TODO split router and issuer
// TODO admin console
// TODO router public key
// TODO write test
// TODO custom exception for handling http response

// TODO gorvp module:
// - router
// - identity provider
// - owner client
// - auth, token (fosite)
// mount above modules in main
