package gorvp

import (
	"time"
	"strings"
)

type Connection struct {
	ID          string      `gorm:"primary_key"`
	UserID      string      `gorm:"index"`
	Client      GoRvpClient `gorm:"ForeignKey:id;AssociationForeignKey:client_id"`
	ClientID    string
	ScopeString string      `gorm:"size:1023"`

	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time  `sql:"index"`
}

func (c *Connection) MergeScope(scopes []string) (string) {
	scopeMap := make(map[string]bool)
	c.addScopeSliceToMap(scopes, scopeMap)
	c.addScopeStringToMap(c.ScopeString, scopeMap)
	scopeSlice := make([]string, len(scopeMap))

	i := 0
	for scope, _ := range scopeMap {
		scopeSlice[i] = scope
		i++
	}
	return strings.Join(scopeSlice, " ")
}

func (c *Connection) addScopeSliceToMap(scopes []string, scopeMap map[string]bool) {
	for _, scope := range scopes {
		scopeMap[scope] = true
	}
}

func (c *Connection) addScopeStringToMap(scopeString string, scopeMap map[string]bool) {
	scopes := strings.Split(scopeString, " ")
	c.addScopeSliceToMap(scopes, scopeMap)
}
