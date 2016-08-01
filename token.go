package gorvp

import (
	"github.com/jinzhu/gorm"
	"time"
	"net/http"
	"github.com/ory-am/fosite/token/jwt"
)

type AuthorizeCode struct {
	Signature string `gorm:"primary_key"`
	DataJSON  string `gorm:"size:4095"`

	UserID    string `gorm:"index"`
	ClientID  string `gorm:"index"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time `sql:"index"`
}

type Token struct {
	Signature    string `gorm:"primary_key"`
	DataJSON     string `gorm:"size:4095"`

	UserID       string `gorm:"index"`
	ClientID     string `gorm:"index"`
	RefreshToken bool

	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time `sql:"index"`
}

type ClientRevocation struct {
	gorm.Model
	ClientID string
	Client   GoRvpClient `gorm:"ForeignKey:id;AssociationForeignKey:client_id"`
}

func GetTokenClaimsFromCode(store *Store, r *http.Request) (*jwt.JWTClaims, *Connection, error) {
	token := r.PostForm.Get("code")
	if token == "" {
		return nil, nil, ErrTokenNotFound
	}
	return getCodeClaims(store, token)
}

func GetTokenClaimsFromRefreshToken(store *Store, r *http.Request) (*jwt.JWTClaims, *Connection, error) {
	token := r.PostForm.Get("refresh_token")
	if token == "" {
		return nil, nil, ErrTokenNotFound
	}
	return getTokenClaims(store, token)
}

func GetTokenClaimsFromBearer(store *Store, r *http.Request) (*jwt.JWTClaims, *Connection, error) {
	token, err := GetBearerToken(r)
	if err != nil {
		return nil, nil, ErrTokenNotFound
	}
	return getTokenClaims(store, token)
}

func getCodeClaims(store *Store, token string) (*jwt.JWTClaims, *Connection, error) {
	// parse token
	parsedToken, err := GetTokenStrategy().Decode(token)
	if err != nil {
		return nil, nil, ErrTokenInvalid
	}

	// check token
	_, err = store.GetAuthorizeCode(parsedToken.Signature)
	if err != nil {
		return nil, nil, ErrTokenInvalid
	}

	// check connection
	claims := jwt.JWTClaimsFromMap(parsedToken.Claims)
	connection, err := store.GetConnectionByID(claims.Get("cni").(string))
	if err != nil {
		return nil, nil, ErrTokenInvalid
	}

	return claims, connection, nil
}

func getTokenClaims(store *Store, token string) (*jwt.JWTClaims, *Connection, error) {
	// parse token
	parsedToken, err := GetTokenStrategy().Decode(token)
	if err != nil {
		return nil, nil, ErrTokenInvalid
	}

	// check token
	_, err = store.GetToken(parsedToken.Signature)
	if err != nil {
		return nil, nil, ErrTokenInvalid
	}

	// check connection
	claims := jwt.JWTClaimsFromMap(parsedToken.Claims)
	connection, err := store.GetConnectionByID(claims.Get("cni").(string))
	if err != nil {
		return nil, nil, ErrTokenInvalid
	}

	return claims, connection, nil
}

