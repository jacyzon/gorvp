package gorvp

import (
	"time"
	"github.com/ory-am/fosite"
	"encoding/json"
)

const AppTypeAndroid = "android"
const AppTypeIos = "ios"
const AppTypeWebApp = "web_app"
const AppTypeWebBackend = "web_backend"
const AppTypeOwner = "owner"

// Grant data
type OAuthData struct {
	RedirectURI string `json:"redirect_uri"`
}

// Grant data
type AndroidData struct {
	StartActivity string `json:"start_activity"`
	PackageName   string `json:"package_name"`
	KeyHash       string `json:"key_hash"`
}

type GoRvpClient struct {
	ID         string `gorm:"primary_key"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  *time.Time `sql:"index"`
	Name       string
	Secret     string
	AppType    string
	Scopes     Scopes `gorm:"-"`
	ScopesJSON string `gorm:"size:1023"`
	Trusted    bool
	OAuthData
	AndroidData
}

type Client interface {
	fosite.Client
	GetFullScopes() *Scopes
	GetAppType() string
	GetPackageName() string
	GetKeyHash() string
	GetStartActivity() string
	IsTrusted() bool
	GetName() string
}

// client interface TODO dedicated client file
func (c *GoRvpClient) TableName() string {
	return "client"
}

// GetID returns the client ID.
func (c *GoRvpClient) GetID() string {
	return c.ID
}

func (c *GoRvpClient) GetName() string {
	return c.Name
}

// return if client is trusted
func (c *GoRvpClient) IsTrusted() bool {
	return c.Trusted
}

// GetHashedSecret returns the hashed secret as it is stored in the store.
func (c *GoRvpClient) GetHashedSecret() []byte {
	return []byte(c.Secret)
}

// Returns the client's allowed redirect URIs.
func (c *GoRvpClient) GetRedirectURIs() []string {
	// TODO refactoring
	if c.AppType == AppTypeAndroid {
		//return []string{"ncku://"}
		// TODO currently fosite does not allows non https as a redirect uri,
		// but https is not necessary needed on Android for redirection,
		// one can register a custom schema which allows user login via browser and redirect the access token
		// back to native app
		return []string{"http://localhost"}
	} else {
		return []string{c.RedirectURI}
	}
}

// Returns the client's allowed grant types.
func (c *GoRvpClient) GetGrantTypes() fosite.Arguments {
	// TODO refactoring
	switch c.AppType {
	case AppTypeWebBackend:
		return []string{"authorization_code", "refresh_token"}
	case AppTypeWebApp:
		return []string{"implicit"}
	case AppTypeAndroid:
		return []string{"implicit", "refresh_token"}
	case AppTypeIos:
		return []string{"implicit", "refresh_token"}
	case AppTypeOwner:
		return []string{"password"}
	}
	return []string{}
}

// Returns the client's allowed response types.
func (c *GoRvpClient) GetResponseTypes() fosite.Arguments {
	// TODO refactoring
	switch c.AppType {
	case AppTypeWebBackend:
		return fosite.Arguments{"code", "token"}
	case AppTypeWebApp:
		return fosite.Arguments{"token"}
	case AppTypeAndroid:
		return fosite.Arguments{"token"}
	case AppTypeIos:
		return fosite.Arguments{"token"}
	case AppTypeOwner:
		return fosite.Arguments{"token"}
	}
	return fosite.Arguments{}
}

// Returns the client's owner.
func (c *GoRvpClient) GetOwner() string {
	// TODO #6 external owner request
	return ""
}

// Returns the scopes this client was granted.
func (c *GoRvpClient) GetScopes() fosite.Arguments {
	scopes := make(fosite.Arguments, len(c.Scopes))
	for i, s := range c.Scopes {
		scopes[i] = s.Name
	}
	return scopes
}

func (c *GoRvpClient) GetFullScopes() *Scopes {
	return &c.Scopes;
}

func (c *GoRvpClient) UnmarshalScopesJSON() {
	json.Unmarshal([]byte(c.ScopesJSON), &c.Scopes)
}

func (c *GoRvpClient) GetAppType() string {
	return c.AppType
}

func (c *GoRvpClient) GetPackageName() string {
	return c.PackageName
}

func (c *GoRvpClient) GetKeyHash() string {
	return c.KeyHash
}

func (c *GoRvpClient) GetStartActivity() string {
	return c.StartActivity
}
