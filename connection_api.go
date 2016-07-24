package gorvp

import (
	"github.com/gorilla/mux"
	"net/http"
	"encoding/json"
	"github.com/jinzhu/gorm"
)

type ConnectionHandler struct {
	Router *mux.Router
	Routes Routes
	Store  *Store
}

type ConnectionResponse struct {
	ID     string            `json:"id"`
	Client GetClientResponse `json:"client"`
}

func (h *ConnectionHandler) GetApplications(w http.ResponseWriter, r *http.Request) {
	claims, err := GetTokenClaims(h.Store, r)
	if err != nil {
		WriteError(w, err)
		return
	}
	connection := &Connection{UserID: claims.Subject}
	connections := []Connection{}
	err = h.Store.DB.Preload("Client").Where(connection).Find(&connections).Error
	if err != nil {
		WriteError(w, err)
		return
	}

	scopeInfoSlice := []ScopeInfo{}
	scopeInfoMap := make(map[string]ScopeInfo)
	h.Store.DB.Find(&scopeInfoSlice)

	for _, scopeInfo := range scopeInfoSlice {
		scopeInfoMap[scopeInfo.Name] = scopeInfo
	}

	connectionsResponse := make([]ConnectionResponse, len(connections))
	for index, c := range connections {
		cr := &connectionsResponse[index]
		cr.ID = c.ID
		cr.Client.ID = c.Client.ID
		cr.Client.Name = c.Client.Name
		cr.Client.LogoUrl = "" // TODO

		scopes := c.Client.GetGrantedScopes().(*Scopes)
		cr.Client.Scopes = make([]ScopeResponse, len(*scopes))
		for index, scope := range *scopes {
			cr.Client.Scopes[index].Name = scope.Name
			cr.Client.Scopes[index].Description = scopeInfoMap[scope.Name].Description
			cr.Client.Scopes[index].DisplayName = scopeInfoMap[scope.Name].DisplayName
			cr.Client.Scopes[index].Required = scope.Required
		}
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connectionsResponse)
}

func (h *ConnectionHandler) RevokeApplication(w http.ResponseWriter, r *http.Request) {
	claims, err := GetTokenClaims(h.Store, r)
	if err != nil {
		WriteError(w, err)
		return
	}

	connectionID := mux.Vars(r)["id"]
	connection := &Connection{ID: connectionID}
	err = h.Store.DB.Find(connection).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			WriteError(w, ErrRecordNotFound)
			return
		}
		WriteError(w, err)
		return
	}
	if connection.UserID != claims.Subject {
		WriteError(w, ErrPermissionDenied)
		return
	}

	err = h.Store.DB.Delete(connection).Error
	if err != nil {
		WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
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
			"Revoke access of application by connection id",
			"DELETE",
			"/{id}",
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
