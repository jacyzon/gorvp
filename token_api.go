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
	claims, _, err := GetTokenClaimsFromBearer(h.Store, r)
	if err != nil {
		WriteError(w, err)
		return
	}
	tokenSignatureToDelete := mux.Vars(r)["signature"]
	tokenOwner := claims.Subject
	tokenToDelete := &Token{Signature: tokenSignatureToDelete}

	// find the token to delete
	err = h.Store.DB.First(tokenToDelete).Error
	if err != nil {
		WriteError(w, err)
		return
	}

	//// user id not match
	if tokenToDelete.UserID != tokenOwner {
		WriteError(w, ErrPermissionDenied)
		return
	}

	// delete token
	err = h.Store.DB.Delete(tokenToDelete).Error
	if err != nil {
		WriteError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *TokenHandler) SetupHandler() {
	h.Routes = Routes{
		Route{
			"Revocate token",
			"DELETE",
			"/{signature}",
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
