package gorvp

import (
	"net/http"
	"github.com/gorilla/mux"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"github.com/pilu/xrequestid"
	"github.com/pborman/uuid"
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

type ScopeResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

type Routes []Route

func (h *AdminHandler) GetClient(w http.ResponseWriter, r *http.Request) {
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
		LogoUrl: "789",
		Scopes: scopeResponseList,
	}
	json.NewEncoder(w).Encode(getClientResponse)
}

func (h *AdminHandler) GetClients(w http.ResponseWriter, r *http.Request) {
}

func (h *AdminHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	createClientRequest := CreateClientRequest{}
	err := decoder.Decode(&createClientRequest)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest);
		return
	}
	// TODO appType to grantTypes and ResponseTypes helper
	// TODO data validation

	// ==================================================================
	// | AppType     | GrantTypes         | ResponseTypes | Data Type   |
	// ------------------------------------------------------------------
	// | web_backend | authorization_code | code, token   | OAuthData   |
	// | web_app     | implicit           | token         | OAuthData   |
	// | android     | implicit           | token         | AndroidData |
	// | ios         | implicit           | token         |             |
	// | trusted     | password           | token         |             |
	// ==================================================================
	client := GoRvpClient{
		ID:      uuid.New(),
		Name:    createClientRequest.Name,
		AppType: createClientRequest.AppType,
	}
	switch createClientRequest.AppType {
	case AppTypeWebBackend:
		client.RedirectURI = createClientRequest.RedirectURI
		break
	case AppTypeWebApp:
		client.RedirectURI = createClientRequest.RedirectURI
		break
	case AppTypeAndroid:
		client.StartActivity = createClientRequest.StartActivity
		client.PackageName = createClientRequest.PackageName
		client.KeyHash = createClientRequest.KeyHash
		break
	case AppTypeIos:
		// not implemented yet
		break
	case AppTypeOwner:
		client.RedirectURI = createClientRequest.RedirectURI
		if createClientRequest.Trusted {
			client.Trusted = createClientRequest.Trusted
		}
		break
	default:
		http.Error(w, "Unsupported app type", http.StatusBadRequest)
		return
	}
	scopeJson, _ := json.Marshal(createClientRequest.Scope)
	client.ScopesJSON = string(scopeJson)

	//grantJson, _ := json.Marshal(&client.Grant)
	//client.GrantJSON = string(grantJson)

	// generate client secret
	unEncryptedSecret, _ := h.Hash.Generate(h.Hash.Size)
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
}

func (h *AdminHandler) DeleteClient(w http.ResponseWriter, r *http.Request) {
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
			"Get clients",
			"GET",
			"/client/{id}",
			h.GetClient,
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