package gorvp

import (
	"net/http"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"github.com/pilu/xrequestid"
)

type AdminHandler struct {
	Router *mux.Router
	Routes Routes
	DB     *gorm.DB
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
	OAuthData
	AndroidData
}

type CreateClientResponse struct {
	Id     uint `json:"id"` // TODO switch to uuid
	Secret string `json:"secret"`
}

type Routes []Route

func (h *AdminHandler) GetClients(w http.ResponseWriter, r *http.Request) {
}

func (h *AdminHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	createClientRequest := CreateClientRequest{}
	err := decoder.Decode(&createClientRequest)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest);
	}
	// TODO appType to grantTypes and ResponseTypes helper
	// TODO data validation

	// ===================================================================
	// | AppType     | GrantTypes         | ResponseTypes | Data Type    |
	// -------------------------------------------------------------------
	// | web_backend | authorization_code | code, token   | OAuthGrant   |
	// | web_app     | implicit           | token         | OAuthGrant   |
	// | android     | implicit           | token         | AndroidGrant |
	// | ios         | implicit           | token         | IOSGrant     |
	// | trusted     | password           | token         |              |
	// ===================================================================
	client := GoRvpClient{
		Name: createClientRequest.Name,
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
	case AppTypeTrusted:
		client.RedirectURI = createClientRequest.RedirectURI
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
	h.DB.Create(&client)

	// create response
	createClientResponse := CreateClientResponse{
		Id:     client.ID,
		Secret: unEncryptedSecret,
	}
	w.Header().Set("Content-Type", "application/javascript")
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