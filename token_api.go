package gorvp

import (
	"github.com/gorilla/mux"
	"net/http"
)

type TokenHandler struct {
	Router *mux.Router
	Routes Routes
	Store  *Store
}

func (h *TokenHandler) TokenRevocation(w http.ResponseWriter, r *http.Request) {
	// TODO
	// parse jwt
	// delete token by id
}

func (h *TokenHandler) SetupHandler() {
	h.Routes = Routes{
		Route{
			"Revocate token",
			"DELETE",
			"/token/{id}",
			h.TokenRevocation,
		},
	}
	for _, route := range h.Routes {
		h.Router.
		Methods(route.Method).
		Path(route.Pattern).
		Name(route.Name).
		Handler(route.HandlerFunc)
	}
}
