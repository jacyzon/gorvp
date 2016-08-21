package gorvp

import (
	"github.com/gorilla/mux"
	"net/http"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/ory-am/fosite/hash"
)

type TokenHandler struct {
	Router *mux.Router
	Routes Routes
	Store  *Store
	Hasher hash.Hasher
}

func (h *TokenHandler) TokenRevocation(w http.ResponseWriter, r *http.Request) {
	tokenSignatureToDelete := mux.Vars(r)["signature"]
	tokenToDelete := &Token{Signature: tokenSignatureToDelete}

	// find the token to delete
	err := h.Store.DB.Preload("Client").First(tokenToDelete).Error
	if err != nil {
		WriteError(w, ErrRecordNotFound)
		return
	}

	// check the request client has permission to delete this token
	var claims *jwt.JWTClaims
	switch tokenToDelete.Client.GetAppType() {
	case AppTypeClient:
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			err = ErrTokenNotFoundBearer
			break
		}

		client, err := h.Store.GetClient(clientID)
		if err != nil {
			err = ErrRecordNotFound
			break
		}

		// Enforce client authentication
		if err := h.Hasher.Compare(client.GetHashedSecret(), []byte(clientSecret)); err != nil {
			err = ErrInvalidClient
			break
		}
	default:
		claims, _, err = GetTokenClaimsFromBearer(h.Store, r)
		if err != nil {
			// fallback to basic auth
			username, password, ok := r.BasicAuth()
			if !ok {
				// basic auth is not provided also
				break
			}
			if tokenToDelete.UserID != username {
				err = ErrPermissionDenied
				break
			}
			if h.Store.Authenticate(nil, username, password) != nil {
				err = ErrPermissionDenied
				break
			}
			err = nil
		} else {
			// user id not match
			if tokenToDelete.UserID != claims.Subject {
				err = ErrPermissionDenied
				break
			}
		}
	}
	if err != nil {
		WriteError(w, err)
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
