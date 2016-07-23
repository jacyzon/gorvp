package gorvp

import (
	"github.com/jinzhu/gorm"
	"time"
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

