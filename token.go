package gorvp

import (
	"github.com/jinzhu/gorm"
	"time"
	"net/http"
	"github.com/ory-am/fosite/token/jwt"
	jwtgo "github.com/dgrijalva/jwt-go"
)

type AuthorizationCode struct {
	Signature string `gorm:"primary_key"`
	DataJSON  string `gorm:"size:4095"`

	UserID    string `gorm:"index"`
	ClientID  string `gorm:"index"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time `sql:"index"`
}

type Token struct {
	Signature    string      `gorm:"primary_key"`
	DataJSON     string      `gorm:"size:4095"`

	UserID       string      `gorm:"index"`
	Client       GoRvpClient `gorm:"ForeignKey:id;AssociationForeignKey:client_id"`
	ClientID     string
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

func JWTClaimsFromMap(m map[string]interface{}) *jwt.JWTClaims {
	return &jwt.JWTClaims{
		Subject:   jwt.ToString(m["sub"]),
		IssuedAt:  jwt.ToTime(m["iat"]),
		Issuer:    jwt.ToString(m["iss"]),
		NotBefore: jwt.ToTime(m["nbf"]),
		Audience:  jwt.ToString(m["aud"]),
		ExpiresAt: jwt.ToTime(m["exp"]),
		JTI:       jwt.ToString(m["jti"]),
		Extra:     jwt.Filter(m, "sub", "iss", "iat", "nbf", "aud", "exp", "jti"),
	}
}

func (t *AuthorizationCode) TableName() string {
	return "oauth_authorization_codes"
}

func (t *Token) TableName() string {
	return "oauth_tokens"
}

func (c *ClientRevocation) TableName() string {
	return "oauth_client_revocations"
}

func GetTokenClaimsFromCode(store *Store, r *http.Request) (*jwt.JWTClaims, *Connection, error) {
	token := r.PostForm.Get("code")
	if token == "" {
		return nil, nil, ErrTokenNotFoundBearer
	}
	return getCodeClaims(store, token)
}

func GetTokenClaimsFromRefreshToken(store *Store, r *http.Request) (*jwt.JWTClaims, *Connection, error) {
	token := r.PostForm.Get("refresh_token")
	if token == "" {
		return nil, nil, ErrTokenNotFoundBearer
	}
	return getTokenClaims(store, token)
}

func GetTokenClaimsFromBearer(store *Store, r *http.Request) (*jwt.JWTClaims, *Connection, error) {
	token, err := GetBearerToken(r)
	if err != nil {
		return nil, nil, ErrTokenNotFoundBearer
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
	claims := JWTClaimsFromMap(parsedToken.Claims.(jwtgo.MapClaims))
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

	// check client
	claims := JWTClaimsFromMap(parsedToken.Claims.(jwtgo.MapClaims))
	_, err = store.GetClient(claims.Audience)
	if err != nil {
		return nil, nil, ErrTokenInvalid
	}

	// check connection
	connection, err := store.GetConnectionByID(claims.Get("cni").(string))
	if err != nil {
		return nil, nil, ErrTokenInvalid
	}

	return claims, connection, nil
}

