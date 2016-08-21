package gorvp

import (
	"github.com/ory-am/fosite"
)

type Scope struct {
	Name     string `json:"name" yaml:"name"`
	Required bool   `json:"required" yaml:"required"`
}

type Scopes []Scope

type ScopeInfo struct {
	Name        string `gorm:"primary_key"`
	DisplayName string
	Description string
}

func (c *ScopeInfo) TableName() string {
	return "oauth_scopes"
}

func (s *Scopes) Grant(requestScopes fosite.Arguments) bool {
	ss := []Scope(*s)
	scopes := make([]string, len(ss))
	for i, scope := range ss {
		scopes[i] = scope.Name
	}
	for _, scope := range requestScopes {
		granted := fosite.HierarchicScopeStrategy(scopes, scope)
		if !granted {
			return false
		}
	}
	return true;
}

func (s *Scopes) AddRequiredScope(requiredScope string) {
	shouldAddRequiredScope := true
	for _, scope := range *s {
		if scope.Name == requiredScope {
			shouldAddRequiredScope = false
			break
		}
	}
	if shouldAddRequiredScope {
		*s = append(*s, Scope{Name: requiredScope, Required: true})
	}
}
