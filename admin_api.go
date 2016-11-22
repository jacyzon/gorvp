package gorvp

import (
	"net/http"
	"github.com/gorilla/mux"
	"encoding/json"
	"github.com/pborman/uuid"
	"github.com/ory-am/fosite"
)

type AdminHandler struct {
	Router *mux.Router
	Routes Routes
	Store  *Store
}

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type CreateClientRequest struct {
	Name    string `json:"name"`
	AppType string `json:"app_type"`
	Scopes  Scopes `json:"scope"`
	Trusted bool   `json:"trusted"`
	OAuthData
	AndroidData
}

type UpdateClientRequest struct {
	// define allowed column to be updated
	Name          string     `json:"name,omitempty"`
	AppType       string     `json:"app_type,omitempty"`
	Scopes        Scopes     `json:"scopes,omitempty"`
	ScopesJSON    string     `json:"-"`
	Trusted       bool       `json:"trusted,omitempty"`
	Public        bool       `json:"public,omitempty"`

	// OAuthData
	RedirectURI   string     `json:"redirect_uri,omitempty"`

	// AndroidData
	StartActivity string     `json:"start_activity,omitempty"`
	PackageName   string     `json:"package_name,omitempty"`
	KeyHash       string     `json:"key_hash,omitempty"`
}

type ScopeResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

type ResetPasswordResponse struct {
	Password string `json:"password"`
}

type Routes []Route

func (h *AdminHandler) Auth(w http.ResponseWriter, r *http.Request) (error) {
	claims, _, err := GetTokenClaimsFromBearer(h.Store, r)
	if err != nil {
		return err
	}
	requestScope := GetScopeArgumentFromClaims(claims)
	if !fosite.HierarchicScopeStrategy(requestScope, "admin") {
		return ErrClientPermission
	}
	return nil
}

func (h *AdminHandler) GetClients(w http.ResponseWriter, r *http.Request) {
	if err := h.Auth(w, r); err != nil {
		WriteError(w, err)
		return
	}
	clients, err := h.Store.GetRvpClients()
	if err != nil {
		WriteError(w, err)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

func (h *AdminHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	if err := h.Auth(w, r); err != nil {
		WriteError(w, err)
		return
	}
	decoder := json.NewDecoder(r.Body)
	createClientRequest := CreateClientRequest{}
	err := decoder.Decode(&createClientRequest)
	if err != nil {
		WriteError(w, ErrInvalidRequest)
		return
	}
	// check if the name is same as the trusted client
	duplicateClient := &GoRvpClient{Name: createClientRequest.Name}
	err = h.Store.DB.Where(duplicateClient).First(duplicateClient).Error
	if err == nil && duplicateClient.Trusted {
		WriteError(w, ErrDuplicateTrustedClientName)
		return
	}

	// TODO data validation
	// ===========================================================================
	// | AppType     | GrantTypes         | ResponseTypes | Data Type   | Public |
	// ---------------------------------------------------------------------------
	// | web_backend | authorization_code | code, token   | OAuthData   | no     |
	// | web_app     | implicit           | token         | OAuthData   | yes    |
	// | android     | implicit           | token         | AndroidData | yes    |
	// | ios         | implicit           | token         |             | yes    |
	// | trusted     | password           | token         |             | no     |
	// | client      | client_credentials | token         |             | no     |
	// ===========================================================================
	client := GoRvpClient{
		ID:      uuid.New(),
		Name:    createClientRequest.Name,
		AppType: createClientRequest.AppType,
	}

	switch createClientRequest.AppType {
	case AppTypeWebBackend:
		client.RedirectURI = createClientRequest.RedirectURI
		client.Public = false
	case AppTypeWebApp:
		client.RedirectURI = createClientRequest.RedirectURI
		client.Public = true
	case AppTypeAndroid:
		client.StartActivity = createClientRequest.StartActivity
		client.PackageName = createClientRequest.PackageName
		client.KeyHash = createClientRequest.KeyHash
		client.Public = true
	case AppTypeIos:
		// not implemented yet
		WriteError(w, ErrUnsupportedAppType)
		return
	case AppTypeOwner:
		client.RedirectURI = createClientRequest.RedirectURI
		client.Public = false
		if createClientRequest.Trusted {
			client.Trusted = createClientRequest.Trusted
		}
	case AppTypeClient:
		client.Public = false
	default:
		WriteError(w, ErrUnsupportedAppType)
		return
	}
	scopeJson, _ := json.Marshal(createClientRequest.Scopes)
	client.ScopesJSON = string(scopeJson)

	//grantJson, _ := json.Marshal(&client.Grant)
	//client.GrantJSON = string(grantJson)

	// generate client secret
	unEncryptedSecret, _ := client.ResetPassword()

	// save new client into database
	h.Store.DB.Create(&client)

	// create response
	createClientResponse := CreateClientResponse{
		ID:     client.ID,
		Secret: unEncryptedSecret,
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(createClientResponse)
}

func (h *AdminHandler) UpdateClient(w http.ResponseWriter, r *http.Request) {
	if err := h.Auth(w, r); err != nil {
		WriteError(w, err)
		return
	}

	// input client
	decoder := json.NewDecoder(r.Body)
	updateClient := UpdateClientRequest{}
	err := decoder.Decode(&updateClient)
	if err != nil {
		WriteError(w, ErrInvalidRequest)
		return
	}
	if updateClient.Scopes != nil {
		scopeJsonBytes, _ := json.Marshal(updateClient.Scopes)
		scopeJson := string(scopeJsonBytes)
		updateClient.ScopesJSON = string(scopeJson)
	}

	// find current client
	vars := mux.Vars(r)
	clientID := vars["id"]
	currentClient, err := h.Store.GetRvpClient(clientID)
	if err != nil {
		WriteError(w, err)
		return
	}

	// change app type is not allowed
	if (updateClient.AppType != "") && (currentClient.AppType != updateClient.AppType) {
		WriteError(w, ErrModAppTypeNotAllowed)
		return
	}

	err = h.Store.DB.Model(&currentClient).Updates(updateClient).Error
	if err != nil {
		WriteError(w, ErrDatabase)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(currentClient)
}

func (h *AdminHandler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	if err := h.Auth(w, r); err != nil {
		WriteError(w, err)
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]
	err := h.Store.DeleteClient(clientID)
	if err != nil {
		WriteError(w, err)
		return
	}
}

func (h *AdminHandler) ResetClientPassword(w http.ResponseWriter, r *http.Request) {
	if err := h.Auth(w, r); err != nil {
		WriteError(w, err)
		return
	}

	vars := mux.Vars(r)
	clientID := vars["id"]
	newPassword, err := h.Store.ResetClientPassword(clientID)
	if err != nil {
		WriteError(w, err)
		return
	}

	resetPasswordResponse := ResetPasswordResponse{Password: newPassword}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resetPasswordResponse)
}

func (h *AdminHandler) SetupHandler() {
	h.Routes = Routes{
		Route{
			"Get clients",
			"GET",
			"/clients",
			h.GetClients,
		},
		Route{
			"Add client",
			"POST",
			"/client",
			h.CreateClient,
		},
		Route{
			"Update client",
			"PATCH",
			"/client/{id}",
			h.UpdateClient,
		},
		Route{
			"Delete client",
			"DELETE",
			"/client/{id}",
			h.DeleteClient,
		},
		Route{
			"Reset client password",
			"POST",
			"/client/{id}/reset_password",
			h.ResetClientPassword,
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