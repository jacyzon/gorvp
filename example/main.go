package main

import (
	"fmt"
	"time"
	"net/http"
	"github.com/urfave/negroni"
	"github.com/xyproto/mooseware"
	"github.com/gorilla/mux"
	"github.com/pilu/xrequestid"
	"github.com/jacyzon/gorvp"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/ory-am/fosite"
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
	"github.com/go-errors/errors"
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

var selectedStrategy = jwtStrategy

// fositeFactory creates a new Fosite instance with all features enabled
func fositeFactory(store *gorvp.DB) fosite.OAuth2Provider {
	// Instantiate a new fosite instance
	f := fosite.NewFosite(store)

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
		AccessTokenStrategy: jwtStrategy,
		AccessTokenStorage:  store,
	})

	return f
}

// This is our fosite instance
var oauth2 fosite.OAuth2Provider

func main() {
	config := gorvp.Config{}
	config.Load("../fixtures/backend.json", "../fixtures/scope.json")
	fmt.Println(config.Backend)
	fmt.Println(config.Scope)

	db, err := gorm.Open("sqlite3", "/tmp/gorm.db")
	if err != nil {
		panic("Cannot open database.")
	}

	store := gorvp.DB{DB: db}
	store.Migrate()

	oauth2 = fositeFactory(&store)

	authRoute := mux.NewRouter()
	authRoute.HandleFunc("/auth", authEndpoint)

	tokenRoute := mux.NewRouter()
	tokenRoute.HandleFunc("/token", tokenEndpoint)

	pingRoute := mux.NewRouter()
	pingRoute.HandleFunc("/v1/ping", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, "pong")
	})

	fooRoute := mux.NewRouter()
	fooRoute.HandleFunc("/v1/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, "bar")
	})

	pubRoute := mux.NewRouter()
	pubRoute.HandleFunc("/v1/pub", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, "pub")
	})

	router := mux.NewRouter()
	router.PathPrefix("/auth").Handler(negroni.New(
		moose.NewMiddleware(true),
		negroni.Wrap(authRoute),
	))
	router.PathPrefix("/token").Handler(negroni.New(
		moose.NewMiddleware(true),
		negroni.Wrap(tokenRoute),
	))
	router.PathPrefix("/v1/ping").Handler(negroni.New(
		moose.NewMiddleware(false),
		negroni.Wrap(pingRoute),
	))
	router.PathPrefix("/v1/foo").Handler(negroni.New(
		negroni.Wrap(fooRoute),
	))
	router.PathPrefix("/v1/pub").Handler(negroni.New(
		negroni.Wrap(pubRoute),
	))

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
	_, token, ok := req.BasicAuth()
	if !ok {
		http.Error(rw, "missing authorization header", http.StatusBadRequest)
		return
	}
	_, err := jwtStrategy.Validate(token)
	if err != nil {
		http.Error(rw, "token is not valid", http.StatusUnauthorized)
		return
	}
	parsedToken, _ := jwtStrategy.Decode(token)

	// check if the token is from trusted client
	jwtClaims := jwt.JWTClaimsFromMap(parsedToken.Claims)
	if !trustedClient[jwtClaims.Audience] {
		http.Error(rw, "client is not trusted", http.StatusForbidden)
		return
	}
	//req.ParseForm()

	// TODO get client app type
	// switch app type
	// if app type eq android
	// check package name, key-hash
	// return start activity


	// TODO check if the user has permission to access admin API, and the request client is also trusted
	// if authorizeRequest.GetScopes().Has("admin") {
	//     http.Error(rw, "you're not allowed to do that", http.StatusForbidden)
	//     return
	// }

	// This context will be passed to all methods.
	ctx := fosite.NewContext()

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeRequest: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}
	// Now that the user is authorized, we set up a session:
	// TODO check all scopes is satisfied with required permissions
	mySessionData := gorvp.NewSession(jwtClaims.Subject, ar.GetScopes())

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	response, err := oauth2.NewAuthorizeResponse(ctx, req, ar, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeResponse: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
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
	mySessionData := gorvp.NewSession("", []string{})

	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	accessRequest, err := oauth2.NewAccessRequest(ctx, req, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Printf("Error occurred in NewAccessRequest: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
		oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := oauth2.NewAccessResponse(ctx, req, accessRequest)
	if err != nil {
		log.Printf("Error occurred in NewAccessResponse: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
		oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

	// All done, send the response.
	oauth2.WriteAccessResponse(rw, accessRequest, response)

	// The client now has a valid access token
}

var trustedClient = map[string]bool{
	"trusted_audience": true,
}
