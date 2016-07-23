package gorvp

import (
	"github.com/gorilla/mux"
	"net/http"
)

type ConnectionHandler struct {
	Router *mux.Router
	Routes Routes
	Store  *Store
}

func (h *ConnectionHandler) GetApplications(w http.ResponseWriter, r *http.Request) {
	// TODO
	// parse jwt
	// select applications by user id
}

func (h *ConnectionHandler) GetApplication(w http.ResponseWriter, r *http.Request) {
	// TODO
	// parse jwt
	// select application by user id
}

func (h *ConnectionHandler) RevokeApplication(w http.ResponseWriter, r *http.Request) {
	// TODO
	// parse jwt
	// delete connection by connection id
}

func (h *ConnectionHandler) SetupHandler() {
	h.Routes = Routes{
		Route{
			"Get all applications granted by current user",
			"GET",
			"/applications",
			h.GetApplications,
		},
		Route{
			"Get application granted by current user",
			"GET",
			"/applications/{id}",
			h.GetApplication,
		},
		Route{
			"Revoke access of application by id",
			"DELETE",
			"/applications/{id}",
			h.RevokeApplication,
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
