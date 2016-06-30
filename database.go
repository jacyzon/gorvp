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
	Grant     Grant `gorm:"-"`
	Scope     Scope `gorm:"-"`
	GrantJSON string `gorm:"size:1023"`
	ScopeJSON string `gorm:"size:511"`
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
	AppType       string `json:"app_type"`
	Data          interface{} `json:"data"`
	// for fosite, may not need to save into database since we can simply do table look-up
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
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

func (db *DB) Migrate() {
	db.DB.AutoMigrate(&Client{})
	db.DB.AutoMigrate(&Token{})
}
