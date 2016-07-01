package gorvp

import (
	"github.com/jinzhu/gorm"
	"github.com/ory-am/fosite"
	"encoding/json"
	"strconv"
	"golang.org/x/net/context"
	"time"
	"strings"
)

type DB struct {
	DB *gorm.DB
}

type Client struct {
	gorm.Model
	Name       string
	Secret     string
	AppType    string `json:"app_type"`
	Scopes     Scopes `gorm:"-"`
	ScopesJSON string `gorm:"size:1023"`
	OAuthData
	AndroidData
}

type AuthorizeCode struct {
	gorm.Model
	Code     string `gorm:"index"`
	DataJSON string `gorm:"size:4095"`
}

type Token struct {
	ID           string `gorm:"primary_key"`

	Signature    string `gorm:"index"`
	DataJSON     string `gorm:"size:4095"`

	ClientID     string `gorm:"index"`
	Revoke       bool
	RefreshToken bool

	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time `sql:"index"`
}

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

type Scope struct {
	Name     string `json:"name"`
	Required bool `json:"required"`
}

type Scopes struct {
	Scopes []Scope
}

func (db *DB) Migrate() {
	db.DB.AutoMigrate(&Client{})
	db.DB.AutoMigrate(&AuthorizeCode{})
	db.DB.AutoMigrate(&Token{})
}

// store
func (db *DB) GetClient(id string) (fosite.Client, error) {
	if id == "" {
		return nil, fosite.ErrNotFound
	}
	intId, _ := strconv.Atoi(id)
	client := &Client{}
	err := db.DB.Where(&Client{
		Model: gorm.Model{
			ID: uint(intId),
		},
	}).First(&client).Error
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	return client, nil
}

func (db *DB) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	dataJSON, _ := json.Marshal(req)
	err := db.DB.Create(&AuthorizeCode{
		Code: code,
		DataJSON: string(dataJSON),
	}).Error
	if err != nil {
		return fosite.ErrServerError
	}
	return nil
}

func (db *DB) GetAuthorizeCodeSession(_ context.Context, code string, _ interface{}) (fosite.Requester, error) {
	var dataJSON string
	err := db.DB.Where(&AuthorizeCode{Code: code }).First(dataJSON).Error
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	req := &fosite.Request{}
	json.Unmarshal([]byte(dataJSON), &req)
	return req, nil
}

func (db *DB) DeleteAuthorizeCodeSession(_ context.Context, code string) error {
	authorizeCode := AuthorizeCode{Code:code}
	err := db.DB.Delete(&authorizeCode).Error
	if err != nil {
		return fosite.ErrNotFound
	}
	return nil
}

func (db *DB) CreateTokenSession(_ context.Context, signature string, req fosite.Requester, refreshToken bool) error {
	dataJSON, _ := json.Marshal(req)
	session := req.GetSession().(*Session)
	err := db.DB.Create(&Token{
		ID: session.JWTClaims.JTI,
		Signature: signature,
		DataJSON: string(dataJSON),
		ClientID: req.GetClient().GetID(),
		Revoke: false,
		RefreshToken: refreshToken,
	}).Error
	if err != nil {
		return fosite.ErrServerError
	}
	return nil
}

func (db *DB) GetTokenSession(_ context.Context, signature string, _ interface{}) (fosite.Requester, error) {
	var dataJSON string
	err := db.DB.Where(&Token{Signature: signature}).First(dataJSON).Error
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	req := &fosite.Request{}
	json.Unmarshal([]byte(dataJSON), &req)
	return req, nil
}

func (db *DB) DeleteTokenSession(_ context.Context, signature string) error {
	token := Token{Signature: signature}
	err := db.DB.Delete(&token).Error
	if err != nil {
		return fosite.ErrNotFound
	}
	return nil
}

func (db *DB) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	return db.CreateTokenSession(ctx, signature, req, false)
}

func (db *DB) GetAccessTokenSession(ctx context.Context, signature string, s interface{}) (fosite.Requester, error) {
	return db.GetTokenSession(ctx, signature, s)
}

func (db *DB) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return db.DeleteTokenSession(ctx, signature)
}

func (db *DB) CreateRefreshTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	return db.CreateTokenSession(ctx, signature, req, true)
}

func (db *DB) GetRefreshTokenSession(ctx context.Context, signature string, s interface{}) (fosite.Requester, error) {
	return db.GetTokenSession(ctx, signature, s)
}

func (db *DB) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return db.DeleteTokenSession(ctx, signature)
}

func (db *DB) CreateImplicitAccessTokenSession(ctx context.Context, code string, req fosite.Requester) error {
	return db.CreateTokenSession(ctx, code, req, false)
}

func (db *DB) Authenticate(_ context.Context, name string, secret string) error {
	// TODO request
	//rel, ok := s.Users[name]
	//if !ok {
	//	return fosite.ErrNotFound
	//}
	//if rel.Password != secret {
	//	return errors.New("Invalid credentials")
	//}
	return nil
}

func (db *DB) PersistAuthorizeCodeGrantSession(ctx context.Context, authorizeCode, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := db.DeleteAuthorizeCodeSession(ctx, authorizeCode); err != nil {
		return err
	} else if err := db.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if err := db.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}
	return nil
}

func (db *DB) PersistRefreshTokenGrantSession(ctx context.Context, originalRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := db.DeleteRefreshTokenSession(ctx, originalRefreshSignature); err != nil {
		return err
	} else if err := db.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if err := db.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}
	return nil
}

// client interface
// GetID returns the client ID.
func (c *Client) GetID() string {
	return string(c.ID);
}

// GetHashedSecret returns the hashed secret as it is stored in the store.
func (c *Client) GetHashedSecret() []byte {
	return []byte(c.Secret)
}

// Returns the client's allowed redirect URIs.
func (c *Client) GetRedirectURIs() []string {
	// TODO refactoring
	if c.AppType == "android" {
		return []string{"ncku://"}
	} else {
		return []string{c.RedirectURI}
	}
}

// Returns the client's allowed grant types.
func (c *Client) GetGrantTypes() fosite.Arguments {
	// TODO refactoring
	switch c.AppType {
	case "web_backend":
		return []string{"authorization_code"}
	case "web_app":
		return []string{"implicit"}
	case "android":
		return []string{"implicit"}
	case "ios":
		return []string{"implicit"}
	case "trusted":
		return []string{"password"}
	}
	return []string{}
}

// Returns the client's allowed response types.
func (c *Client) GetResponseTypes() fosite.Arguments {
	// TODO refactoring
	switch c.AppType {
	case "web_backend":
		return fosite.Arguments{"code", "token"}
	case "web_app":
		return fosite.Arguments{"token"}
	case "android":
		return fosite.Arguments{"token"}
	case "ios":
		return fosite.Arguments{"token"}
	case "trusted":
		return fosite.Arguments{"token"}
	}
	return fosite.Arguments{}
}

// Returns the client's owner.
func (c *Client) GetOwner() string {
	return ""
}

// Returns the scopes this client was granted.
func (c *Client) GetGrantedScopes() fosite.Scopes {
	json.Unmarshal([]byte(c.ScopesJSON), &c.Scopes)
	return &c.Scopes;
}

func (s *Scopes) Grant(requestScope string) bool {
	// TODO refactoring
	//return true
	for _, scope := range s.Scopes {
		// foo == foo -> true
		if scope.Name == requestScope {
			return true
		}

		// picture.read > picture -> false (scope picture includes read, write, ...)
		if len(scope.Name) > len(requestScope) {
			continue
		}

		needles := strings.Split(requestScope, ".")
		haystack := strings.Split(scope.Name, ".")
		haystackLen := len(haystack) - 1
		for k, needle := range needles {
			if haystackLen < k {
				return true
			}

			current := haystack[k]
			if current != needle {
				continue
			}
		}
	}
	return false
}
