package main

import (
	"fmt"
	"github.com/urfave/negroni"
	"github.com/xyproto/mooseware"
	"github.com/gorilla/mux"
	"net/http"
	"github.com/pilu/xrequestid"
	"github.com/jacyzon/gorvp"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

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

	authRoute := mux.NewRouter()
	authRoute.HandleFunc("/v1/auth", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, "Bafflesnark!")
	})

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
	router.PathPrefix("/v1/auth").Handler(negroni.New(
		moose.NewMiddleware(true),
		negroni.Wrap(authRoute),
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
