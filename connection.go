package gorvp

import "time"

type Connection struct {
	ID         string `gorm:"primary_key"`
	UserID     string `gorm:"index"`
	Client     GoRvpClient
	Scopes     Scopes `gorm:"-"`
	ScopesJSON string `gorm:"size:1023"`

	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  *time.Time `sql:"index"`
}
