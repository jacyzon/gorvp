package gorvp

import (
	"github.com/jinzhu/gorm"
	"time"
	"net/http"
	"github.com/ory-am/fosite/token/jwt"
)

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

func GetTokenClaims(store *Store, r *http.Request) (*jwt.JWTClaims, error) {
	// get token
	token, err := GetBearerToken(r)
	if err != nil {
		return nil, ErrTokenNotFound
	}
	// parse token
	parsedToken, err := GetTokenStrategy().Decode(token)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	claims := jwt.JWTClaimsFromMap(parsedToken.Claims)

	// check token
	tokenToFind := &Token{ID: claims.JTI}
	err = store.DB.First(tokenToFind).Error
	if err != nil {
		return nil, ErrTokenInvalid
	}

	// check connection
	_, err = store.GetConnectionByID(claims.Get("cni").(string))
	if err != nil {
		return nil, ErrTokenInvalid
	}

	return claims, nil
}