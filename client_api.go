package gorvp

import (
	"github.com/gorilla/mux"
	"net/http"
	"encoding/json"
)

type ClientHandler struct {
	Router *mux.Router
	Routes Routes
	Store  *Store
}

type CreateClientResponse struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

type GetClientResponse struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	LogoUrl string          `json:"logo_url"`
	Scopes  []ScopeResponse `json:"scopes"`
}

func (h *ClientHandler) SetupHandler() {
	h.Routes = Routes{
		Route{
			"Get client",
			"GET",
			"/{id}",
			h.GetClient,
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

func (h *ClientHandler) GetClient(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["id"]

	client, err := h.Store.GetClient(clientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var scopeString []string
	scopeMapRequired := make(map[string]bool)

	scopes := *client.GetGrantedScopes().(*Scopes)
	for _, scope := range scopes {
		scopeString = append(scopeString, scope.Name)
		scopeMapRequired[scope.Name] = scope.Required
	}

	var scopeInfoSlice []ScopeInfo
	h.Store.DB.Where("name in (?)", scopeString).Find(&scopeInfoSlice)

	var scopeResponseList []ScopeResponse
	for _, scopeInfo := range scopeInfoSlice {
		scopeResponseList = append(scopeResponseList, ScopeResponse{
			Name:        scopeInfo.Name,
			DisplayName: scopeInfo.DisplayName,
			Description: scopeInfo.Description,
			Required:    scopeMapRequired[scopeInfo.Name],
		})
	}

	getClientResponse := &GetClientResponse{
		ID: clientID,
		Name: client.(Client).GetName(),
		LogoUrl: "", // TODO default client logo
		Scopes: scopeResponseList,
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getClientResponse)
}
