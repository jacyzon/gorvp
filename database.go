package gorvp

import (
	"github.com/jinzhu/gorm"
	"time"
)

type DB struct {
	DB *gorm.DB
}

type Client struct {
	gorm.Model
	Name      string
	Secret    string
	Grant     Grant  `gorm:"-"`
	GrantJSON string `gorm:"size:1023"`
}

type Token struct {
	ID         string `gorm:"primary_key"`
	UserID     string `gorm:"index"`
	Client     Client
	ClientID   string `gorm:"index"`
	Revoke     bool
	IssueDate  time.Time
	ExpireDate time.Time
}

type Grant struct {
	AppType string `json:"app_type"`
	Data    interface{} `json:"data"`
}

type OAuthGrant struct {
	RedirectURI string `json:"redirect_uri"`
	GrantForFosite
}

type AndroidGrant struct {
	StartActivity string `json:"start_activity"`
	PackageName   string `json:"package_name"`
	KeyHash       string `json:"key_hash"`
	GrantForFosite
}

type GrantForFosite struct {
	// for fosite, may not need to save into database since we can simply do table look-up
	ResponseTypes []string `json:"key_hash"`
	GrantTypes    []string `json:"grant_types"`
}

func (db *DB) Migrate() {
	db.DB.AutoMigrate(&Client{})
	db.DB.AutoMigrate(&Token{})
}
