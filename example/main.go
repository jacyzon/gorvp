package main

import (
	"time"
	"net/http"
	"github.com/urfave/negroni"
	"github.com/gorilla/mux"
	"github.com/pilu/xrequestid"
	"github.com/jacyzon/gorvp"
	"github.com/jacyzon/gorvp/example/ident"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	core "github.com/ory-am/fosite/handler/oauth2"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/token/jwt"
	"log"
	"github.com/pkg/errors"
	"fmt"
	"github.com/ory-am/fosite/compose"
)

var gorvpConfig = &gorvp.Config{
	ConfigPath: "../fixtures/config.yaml",
}

type stackTracer interface {
	StackTrace() errors.StackTrace
}

var oauth2 fosite.OAuth2Provider
var store gorvp.Store
var config = &compose.Config{
	AccessTokenLifespan: time.Hour,
	RefreshTokenLifespan: time.Hour,
	AuthorizeCodeLifespan: time.Hour,
}

func main() {
	gorvpConfig.Load()
	gorvpConfig.GenerateRsaKeyIfNotExist()

	jwtInternalStrategy := &core.RS256JWTStrategy{
		RS256JWTStrategy: &jwt.RS256JWTStrategy{
			PrivateKey: gorvpConfig.RsaKey.Proxy.Key,
		},
	}

	tokenStrategy := &core.RS256JWTStrategy{
		RS256JWTStrategy: &jwt.RS256JWTStrategy{
			PrivateKey: gorvpConfig.RsaKey.Token.Key,
		},
	}

	gorvp.SetupSites(gorvpConfig)
	gorvp.SetTokenStrategy(tokenStrategy)

	db, err := gorm.Open(gorvpConfig.Database.Type, gorvpConfig.Database.Connection)
	db.LogMode(true)
	if err != nil {
		panic("Cannot open database.")
	}

	store = gorvp.Store{
		DB: db,
		MandatoryScope: "gorvp",
	}
	store.Migrate()
	store.CreateScopeInfo(gorvpConfig)
	id, secret, err := store.CreateTrustedClient("gorvp_api")
	if err == nil {
		// TODO log lib
		fmt.Printf("default trusted api client id: %s, secret: %s\n", id, secret)
	}
	oauth2 = compose.Compose(
		config,
		&store,
		&compose.CommonStrategy{
			// alternatively you could use OAuth2Strategy: compose.NewOAuth2JWTStrategy(mustRSAKey())
			CoreStrategy: tokenStrategy,
		},
		// enabled handlers
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2ResourceOwnerPasswordCredentialsFactory,
	)
	oc := &gorvp.OwnerClient{
		JWTStrategy:          jwtInternalStrategy,
		IdentityProviderName: "gorvp_identity_provider",
		ClientID:             id,
		ClientSecret:         secret,
		MandatoryScope:       "gorvp",
		TokenEndpoint:        "http://localhost:3000/token",
		IdentityEndpoint:     "http://localhost:3000/ident",
		ReNewTokenDuration:    time.Minute * 30,
	}
	store.OC = oc

	// TODO use different one from token issuer, for internal trustworthy
	identity := &ident.IdentityProvider{jwtInternalStrategy}

	router := mux.NewRouter()
	router.PathPrefix("/auth").Handler(negroni.New(
		// TODO add limit plugin
		negroni.Wrap(oc),
	))
	router.HandleFunc("/ident", identity.ServeHTTP)
	router.HandleFunc("/oauth", authEndpoint)
	router.HandleFunc("/token", tokenEndpoint)

	// TODO plugins support
	jwtProxy := gorvp.NewJwtProxy(&store, tokenStrategy, gorvpConfig)
	m := negroni.New(jwtProxy)
	gorvpConfig.SetupRoute(router, m)

	// admin API
	adminHandler := gorvp.AdminHandler{
		Router:router.PathPrefix("/admin").Subrouter(),
		Store: &store,
		Hash: xrequestid.New(16),
		MandatoryScope: "gorvp",
	}
	adminHandler.SetupHandler()

	clientHandler := gorvp.ClientHandler{
		Router:router.PathPrefix("/client").Subrouter(),
		Store: &store,
	}
	clientHandler.SetupHandler()

	tokenHandler := gorvp.TokenHandler{
		Router:router.PathPrefix("/token").Subrouter(),
		Store: &store,
	}
	tokenHandler.SetupHandler()

	connectionHandler := gorvp.ConnectionHandler{
		Router:router.PathPrefix("/connections").Subrouter(),
		Store: &store,
	}
	connectionHandler.SetupHandler()

	// attach basic middleware
	n := negroni.New(negroni.NewRecovery(), negroni.NewLogger(), xrequestid.New(16), negroni.Wrap(router))
	n.Run(":3000")
}

func authEndpoint(rw http.ResponseWriter, req *http.Request) {
	jwtClaims, _, err := gorvp.GetTokenClaimsFromBearer(&store, req)
	if err != nil {
		gorvp.WriteError(rw, err)
		return
	}

	// This context will be passed to all methods.
	ctx := fosite.NewContext()

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	req.ParseForm()
	ar, err := oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeRequest: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	// check if the token is from trusted client
	authTokenClient, err := store.GetClient(jwtClaims.Audience)
	if err != nil {
		http.Error(rw, "token is invalid", http.StatusUnauthorized)
		return
	}
	authTokenRVPClient := authTokenClient.(gorvp.Client)
	if !authTokenRVPClient.IsTrusted() {
		http.Error(rw, "client is not trusted", http.StatusForbidden)
		return
	}

	// check scopes
	err = gorvp.GrantScope(oauth2, ar)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	requestClient := ar.GetClient().(gorvp.Client)
	clientID := requestClient.GetID()
	grantedScopes := ar.GetGrantedScopes()

	connection, err := store.UpdateConnection(clientID, jwtClaims.Subject, grantedScopes)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	// Now that the user is authorized, we set up a session:
	session := gorvp.NewSession(config, jwtClaims.Subject, grantedScopes, requestClient.GetID(), connection)

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	response, err := oauth2.NewAuthorizeResponse(ctx, req, ar, session)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeResponse: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	// check app type and relevant check
	validClient := true
	switch requestClient.GetAppType() {
	case gorvp.AppTypeAndroid:
		if requestClient.GetPackageName() != ar.GetRequestForm().Get("package_name") {
			validClient = false
		} else if requestClient.GetKeyHash() != ar.GetRequestForm().Get("key_hash") {
			validClient = false
		}
		if validClient {
			response.AddFragment("start_activity", requestClient.GetStartActivity())
		} else {
			http.Error(rw, "not valid client", http.StatusForbidden)
			return
		}
	}

	// Last but not least, send the response!
	oauth2.WriteAuthorizeResponse(rw, ar, response)
}

func tokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := fosite.NewContext()

	// Create an empty session object which will be passed to the request handlers
	session := gorvp.NewSession(config, "", []string{}, "", &gorvp.Connection{})

	// TODO refactoring
	req.ParseForm()
	grantType := req.PostForm.Get("grant_type")
	if grantType == "refresh_token" {
		_, _, ok := req.BasicAuth()
		if !ok {
			claims, connection, err := gorvp.GetTokenClaimsFromRefreshToken(&store, req)
			if err != nil {
				gorvp.WriteError(rw, err)
				return
			}
			// bypass client check if the app type of client is android or ios
			req.SetBasicAuth(claims.Audience, "0c931a6eecc26f13eba386cd92dae809")

			session.CopyScopeFromClaims(claims)
			session.JWTClaims.Audience = claims.Audience
			session.JWTClaims.Subject = claims.Subject
			session.SetConnection(connection)
		}
	}

	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	ar, err := oauth2.NewAccessRequest(ctx, req, session)

	if err != nil {
		log.Printf("Error occurred in NewAccessRequest: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
		oauth2.WriteAccessError(rw, ar, err)
		return
	}

	// TODO refactoring: select app type
	if ar.GetGrantTypes().Exact("password") {
		clientID := ar.GetClient().GetID()
		username := req.PostForm.Get("username")
		ar.GrantScope("password")
		connection, err := store.UpdateConnection(clientID, username, ar.GetGrantedScopes())
		if err != nil {
			gorvp.WriteError(rw, err)
			return
		}
		session.SetScopes(ar.GetGrantedScopes())
		session.JWTClaims.Audience = clientID
		session.JWTClaims.Subject = username
		session.SetConnection(connection)
	} else if ar.GetGrantTypes().Exact("authorization_code") {
		claims, connection, err := gorvp.GetTokenClaimsFromCode(&store, req)
		if err != nil {
			gorvp.WriteError(rw, err)
			return
		}
		session.CopyScopeFromClaims(claims)
		session.JWTClaims.Audience = claims.Audience
		session.JWTClaims.Subject = claims.Subject
		session.SetConnection(connection)
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := oauth2.NewAccessResponse(ctx, req, ar)
	if err != nil {
		log.Printf("Error occurred in NewAccessResponse: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
		oauth2.WriteAccessError(rw, ar, err)
		return
	}

	// All done, send the response.
	oauth2.WriteAccessResponse(rw, ar, response)

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
