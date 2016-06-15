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
	OAuthGrant
	AndroidGrant
}

type CreateClientResponse struct {
	Secret string
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
	// TODO remove into helper
	// TODO check data validation

	// ================================================================
	// | AppType  | GrantTypes         | ResponseTypes | Data Type    |
	// ----------------------------------------------------------------
	// | web      | authorization_code | code, token   | OAuthGrant   |
	// | web_app  | implicit           | token         | OAuthGrant   |
	// | android  | android            | token         | AndroidGrant |
	// | ios      | ios                | token         | IOSGrant     |
	// | trusted  | password           | token         |              |
	// ================================================================
	client := Client{
		Name: createClientRequest.Name,
		Grant: Grant{
			AppType: createClientRequest.AppType,
		},
	}
	switch createClientRequest.AppType {
	case "web":
		client.Grant.Data = OAuthGrant{
			RedirectURI: createClientRequest.RedirectURI,
			GrantForFosite: GrantForFosite{
				GrantTypes: []string{"authorization_code"},
				ResponseTypes: []string{"code", "token"},
			},
		}
		break
	case "web_app":
		client.Grant.Data = OAuthGrant{
			RedirectURI: createClientRequest.RedirectURI,
			GrantForFosite: GrantForFosite{
				GrantTypes: []string{"implicit"},
				ResponseTypes: []string{"token"},
			},
		}
		break
	case "android":
		client.Grant.Data = OAuthGrant{
			RedirectURI: createClientRequest.RedirectURI,
			GrantForFosite: GrantForFosite{
				GrantTypes: []string{"android"},
				ResponseTypes: []string{"token"},
			},
		}
		break
	case "ios":
		// not implemented yet
		break
	case "trusted":
		client.Grant.Data = OAuthGrant{
			RedirectURI: createClientRequest.RedirectURI,
			GrantForFosite: GrantForFosite{
				GrantTypes: []string{"password"},
				ResponseTypes: []string{"token"},
			},
		}
		break
	}

	// generate client secret
	unEncryptedSecret, _ := h.Hash.Generate(h.Hash.Size)
	secret, _ := bcrypt.GenerateFromPassword([]byte(unEncryptedSecret), 10)
	secretString := string(secret)
	client.Secret = secretString

	// save new client into database
	grantJson, _ := json.Marshal(&client.Grant)
	client.GrantJSON = string(grantJson)
	h.DB.Create(&client)

	// create response
	createClientResponse := CreateClientResponse{Secret: unEncryptedSecret}
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