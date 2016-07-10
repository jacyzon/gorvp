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
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/hash"
	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/owner"
	"github.com/ory-am/fosite/handler/core/refresh"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/implicit"
	coreclient "github.com/ory-am/fosite/handler/core/client"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/ory-am/fosite/handler/core/strategy"
	"crypto/rsa"
	"crypto/rand"
	"log"
	"github.com/pkg/errors"
	"fmt"
)

func MustRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	return key
}

var jwtStrategy = &strategy.RS256JWTStrategy{
	RS256JWTStrategy: &jwt.RS256JWTStrategy{
		PrivateKey: MustRSAKey(),
	},
}

var jwtInternalStrategy = &strategy.RS256JWTStrategy{
	RS256JWTStrategy: &jwt.RS256JWTStrategy{
		PrivateKey: MustRSAKey(),
	},
}

type stackTracer interface {
	StackTrace() errors.StackTrace
}

var selectedStrategy = jwtStrategy

// fositeFactory creates a new Fosite instance with all features enabled
func fositeFactory(store *gorvp.DB) fosite.OAuth2Provider {
	// Instantiate a new fosite instance
	f := &fosite.Fosite{
		Store:                       store,
		MandatoryScope:              "gorvp", // TODO - move mandatory scope into config
		AuthorizeEndpointHandlers:   fosite.AuthorizeEndpointHandlers{},
		TokenEndpointHandlers:       fosite.TokenEndpointHandlers{},
		AuthorizedRequestValidators: fosite.AuthorizedRequestValidators{},
		Hasher: &hash.BCrypt{WorkFactor: 12},
	}

	// Set the default access token lifespan to one hour
	accessTokenLifespan := time.Hour

	// Most handlers are composable. This little helper is used by some of the handlers below.
	oauth2HandleHelper := &core.HandleHelper{
		AccessTokenStrategy: selectedStrategy,
		AccessTokenStorage:  store,
		AccessTokenLifespan: accessTokenLifespan,
	}

	// This handler is responsible for the authorization code grant flow
	explicitHandler := &explicit.AuthorizeExplicitGrantTypeHandler{
		AccessTokenStrategy:       selectedStrategy,
		RefreshTokenStrategy:      selectedStrategy,
		AuthorizeCodeStrategy:     selectedStrategy,
		AuthorizeCodeGrantStorage: store,
		AuthCodeLifespan:          time.Minute * 10,
		AccessTokenLifespan:       accessTokenLifespan,
	}
	// In order to "activate" the handler, we need to add it to fosite
	f.AuthorizeEndpointHandlers.Append(explicitHandler)

	// Because this handler both handles `/auth` and `/token` endpoint requests, we need to add him to
	// both registries.
	f.TokenEndpointHandlers.Append(explicitHandler)

	// This handler is responsible for the implicit flow. The implicit flow does not return an authorize code
	// but instead returns the access token directly via an url fragment.
	implicitHandler := &implicit.AuthorizeImplicitGrantTypeHandler{
		AccessTokenStrategy: selectedStrategy,
		AccessTokenStorage:  store,
		AccessTokenLifespan: accessTokenLifespan,
	}
	f.AuthorizeEndpointHandlers.Append(implicitHandler)

	// This handler is responsible for the client credentials flow. This flow is used when you want to
	// authorize a client instead of an user.
	clientHandler := &coreclient.ClientCredentialsGrantHandler{
		HandleHelper: oauth2HandleHelper,
	}
	f.TokenEndpointHandlers.Append(clientHandler)

	// This handler is responsible for the resource owner password credentials grant. In general, this
	// is a flow which should not be used but could be useful in legacy environments. It uses a
	// user's credentials (username, password) to issue an access token.
	ownerHandler := &owner.ResourceOwnerPasswordCredentialsGrantHandler{
		HandleHelper:                                 oauth2HandleHelper,
		ResourceOwnerPasswordCredentialsGrantStorage: store,
	}
	f.TokenEndpointHandlers.Append(ownerHandler)

	// This handler is responsible for the refresh token grant. This type is used when you want to exchange
	// a refresh token for a new refresh token and a new access token.
	refreshHandler := &refresh.RefreshTokenGrantHandler{
		AccessTokenStrategy:      selectedStrategy,
		RefreshTokenStrategy:     selectedStrategy,
		RefreshTokenGrantStorage: store,
		AccessTokenLifespan:      accessTokenLifespan,
	}
	f.TokenEndpointHandlers.Append(refreshHandler)

	// Add a request validator for Access Tokens to fosite
	f.AuthorizedRequestValidators.Append(&core.CoreValidator{
		AccessTokenStrategy: selectedStrategy,
		AccessTokenStorage:  store,
	})

	return f
}

// This is our fosite instance
var oauth2 fosite.OAuth2Provider
var store gorvp.DB

func main() {
	config := &gorvp.Config{}
	config.Load("../fixtures/backend.json")

	gorvp.SetupSites(config)

	db, err := gorm.Open("sqlite3", "/tmp/gorm.db")
	if err != nil {
		panic("Cannot open database.")
	}

	store = gorvp.DB{DB: db}
	store.Migrate()
	oauth2 = fositeFactory(&store)

	id, secret, err := store.CreateTrustedClient("gorvp_api")
	if err == nil {
		// TODO log lib
		fmt.Printf("default trusted api client id: %s, secret: %s\n", id, secret)
	}
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
	jwtProxy := gorvp.NewJwtProxy(selectedStrategy, config)
	m := negroni.New(jwtProxy)
	config.SetupRoute(router, m)

	// admin API
	adminHandler := gorvp.AdminHandler{
		Router:router.PathPrefix("/admin").Subrouter(),
		DB: db,
		Hash: xrequestid.New(16),
	}
	adminHandler.SetupHandler()

	// attach basic middleware
	n := negroni.New(negroni.NewRecovery(), negroni.NewLogger(), xrequestid.New(16), negroni.Wrap(router))
	n.Run(":3000")
}

func authEndpoint(rw http.ResponseWriter, req *http.Request) {
	// validate token
	token, err := gorvp.GetBearerToken(req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	parsedToken, err := jwtStrategy.Decode(token)
	if err != nil {
		http.Error(rw, "token is invalid", http.StatusUnauthorized)
		return
	}
	jwtClaims := jwt.JWTClaimsFromMap(parsedToken.Claims)

	// TODO check if the user has permission to access admin API, and the request client is also trusted
	// if authorizeRequest.GetScopes().Has("admin") {
	//     http.Error(rw, "you're not allowed to do that", http.StatusForbidden)
	//     return
	// }

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

	// Now that the user is authorized, we set up a session:
	session := gorvp.NewSession(jwtClaims.Subject, ar.GetGrantedScopes(), requestClient.GetID())

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	response, err := oauth2.NewAuthorizeResponse(ctx, req, ar, session)

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

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeResponse: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	// Last but not least, send the response!
	oauth2.WriteAuthorizeResponse(rw, ar, response)
}

func tokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := fosite.NewContext()

	// Create an empty session object which will be passed to the request handlers
	session := gorvp.NewSession("", []string{}, "")

	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	ar, err := oauth2.NewAccessRequest(ctx, req, session)

	if ar.GetGrantTypes().Exact("password") {
		ar.GrantScope(oauth2.GetMandatoryScope() + "_password")
	} else {
		err = gorvp.GrantScope(oauth2, ar)
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}

	username := req.PostForm.Get("username")
	session.JWTClaims.Audience = ar.GetClient().GetID()
	session.JWTClaims.Subject = username
	gorvp.SetScopesInJWT(ar.GetGrantedScopes(), session)


	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Printf("Error occurred in NewAccessRequest: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
		oauth2.WriteAccessError(rw, ar, err)
		return
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

// TODO gorvp module:
// - router
// - identity provider
// - owner client
// - auth, token (fosite)
// mount above modules in main
