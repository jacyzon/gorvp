package gorvp

import (
	"github.com/jinzhu/gorm"
	"time"
	"net/http"
	"github.com/ory-am/fosite/token/jwt"
	"fmt"
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

func GetTokenClaims(r *http.Request) (*jwt.JWTClaims, error) {
	token, err := GetBearerToken(r)
	fmt.Println(token)
	if err != nil {
		return nil, ErrTokenNotFound
	}
	parsedToken, err := GetTokenStrategy().Decode(token)
	fmt.Println(parsedToken)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	return jwt.JWTClaimsFromMap(parsedToken.Claims), nil
}