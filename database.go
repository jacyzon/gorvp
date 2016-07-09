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

type GoRvpClient struct {
	gorm.Model
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
	GetAppType() string
	GetPackageName() string
	GetKeyHash() string
	GetStartActivity() string
	IsTrusted() bool
}

const AppTypeAndroid = "android"
const AppTypeIos = "ios"
const AppTypeWebApp = "web_app"
const AppTypeWebBackend = "web_backend"
const AppTypeOwner = "owner"

type AuthorizeCode struct {
	gorm.Model
	Code     string `gorm:"index"`
	DataJSON string `gorm:"size:4095"`
}

type Token struct {
	ID           string `gorm:"primary_key"`

	Signature    string `gorm:"index"`
	DataJSON     string `gorm:"size:4095"`

	UserID       string `gorm:"index"`
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

type Scopes []Scope

func (db *DB) Migrate() {
	db.DB.AutoMigrate(&GoRvpClient{})
	db.DB.AutoMigrate(&AuthorizeCode{})
	db.DB.AutoMigrate(&Token{})
}

// store
func (db *DB) GetClient(id string) (fosite.Client, error) {
	if id == "" {
		return nil, fosite.ErrNotFound
	}
	intId, _ := strconv.Atoi(id)
	client := &GoRvpClient{}
	err := db.DB.Where(&GoRvpClient{
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
		UserID: req.GetRequestForm().Get("username"), // TODO or token subject
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

func (c *GoRvpClient) TableName() string {
	return "client"
}

// GetID returns the client ID.
func (c *GoRvpClient) GetID() string {
	return strconv.Itoa(int(c.ID))
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
		return []string{"authorization_code"}
	case AppTypeWebApp:
		return []string{"implicit"}
	case AppTypeAndroid:
		return []string{"implicit"}
	case AppTypeIos:
		return []string{"implicit"}
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
func (c *GoRvpClient) GetGrantedScopes() fosite.Scopes {
	json.Unmarshal([]byte(c.ScopesJSON), &c.Scopes)
	return &c.Scopes;
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

func (s *Scopes) Grant(requestScope string) bool {
	ss := []Scope(*s)
	scopes := make([]string, len(ss))
	for i, scope := range ss {
		scopes[i] = scope.Name
	}
	return CheckGrant(scopes, requestScope)
}

func CheckGrant(scopes []string, requestScope string) bool {
	for _, scope := range scopes {
		if scope == "" {
			break
		}
		// foo == foo -> true
		if scope == requestScope {
			return true
		}

		// picture.read > picture -> false (scope picture includes read, write, ...)
		if len(scope) > len(requestScope) {
			continue
		}

		needles := strings.Split(requestScope, ".")
		haystack := strings.Split(scope, ".")
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