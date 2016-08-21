package gorvp

import (
	"net/http"
	"github.com/gorilla/mux"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"github.com/pilu/xrequestid"
	"github.com/pborman/uuid"
	"github.com/ory-am/fosite"
)

type AdminHandler struct {
	Router *mux.Router
	Routes Routes
	Store  *Store
	Hash   *xrequestid.XRequestID
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
	Scope   Scopes `json:"scope"`
	Trusted bool   `json:"trusted"`
	OAuthData
	AndroidData
}

type ScopeResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
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
	// ==================================================================
	// | AppType     | GrantTypes         | ResponseTypes | Data Type   |
	// ------------------------------------------------------------------
	// | web_backend | authorization_code | code, token   | OAuthData   |
	// | web_app     | implicit           | token         | OAuthData   |
	// | android     | implicit           | token         | AndroidData |
	// | ios         | implicit           | token         |             |
	// | trusted     | password           | token         |             |
	// | client      | client_credentials | token         |             |
	// ==================================================================
	client := GoRvpClient{
		ID:      uuid.New(),
		Name:    createClientRequest.Name,
		AppType: createClientRequest.AppType,
	}
	var unEncryptedSecret string
	switch createClientRequest.AppType {
	case AppTypeWebBackend:
		client.RedirectURI = createClientRequest.RedirectURI
	case AppTypeWebApp:
		client.RedirectURI = createClientRequest.RedirectURI
	case AppTypeAndroid:
		client.StartActivity = createClientRequest.StartActivity
		client.PackageName = createClientRequest.PackageName
		client.KeyHash = createClientRequest.KeyHash
		// TODO
		unEncryptedSecret = "0c931a6eecc26f13eba386cd92dae809"
	case AppTypeIos:
		// not implemented yet
		// TODO
		unEncryptedSecret = "0c931a6eecc26f13eba386cd92dae809"
	case AppTypeOwner:
		client.RedirectURI = createClientRequest.RedirectURI
		if createClientRequest.Trusted {
			client.Trusted = createClientRequest.Trusted
		}
	case AppTypeClient:
		// no additional infomation needed for client credential type
	default:
		WriteError(w, ErrUnsupportedAppType)
		return
	}
	scopeJson, _ := json.Marshal(createClientRequest.Scope)
	client.ScopesJSON = string(scopeJson)

	//grantJson, _ := json.Marshal(&client.Grant)
	//client.GrantJSON = string(grantJson)

	// generate client secret
	if unEncryptedSecret == "" {
		unEncryptedSecret, _ = h.Hash.Generate(h.Hash.Size)
	}
	secret, _ := bcrypt.GenerateFromPassword([]byte(unEncryptedSecret), 10)
	secretString := string(secret)
	client.Secret = secretString

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
}

func (h *AdminHandler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	if err := h.Auth(w, r); err != nil {
		WriteError(w, err)
		return
	}
}

func (h *AdminHandler) SetupHandler() {
	h.Routes = Routes{
		Route{
			"Get clients",
			"GET",
			"/client",
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
			"/client",
			h.UpdateClient,
		},
		Route{
			"Delete client",
			"DELETE",
			"/client",
			h.DeleteClient,
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