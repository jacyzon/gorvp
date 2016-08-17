package gorvp

import (
	"strings"
)

type Scope struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
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

func (s *Scopes) Grant(requestScope string) bool {
	ss := []Scope(*s)
	scopes := make([]string, len(ss))
	for i, scope := range ss {
		scopes[i] = scope.Name
	}
	return checkGrant(scopes, requestScope)
}

func (s *Scopes) AddMandatoryScope(mandatoryScope string) {
	shouldAddMandatoryScope := true
	for _, scope := range *s {
		if scope.Name == mandatoryScope {
			shouldAddMandatoryScope = false
			break
		}
	}
	if shouldAddMandatoryScope {
		*s = append(*s, Scope{Name: mandatoryScope, Required: true})
	}
}

func checkGrant(scopes []string, requestScope string) bool {
	for _, scope := range scopes {
		if scope == "" {
			break
		}
		// foo == foo -> true
		if scope == requestScope {
			return true
		}

		// picture.read > picture -> false (scope picture includes read, write, ...)
		if len(scope) > len(requestScope) {
			continue
		}

		needles := strings.Split(requestScope, ".")
		haystack := strings.Split(scope, ".")
		haystackLen := len(haystack) - 1
		for k, needle := range needles {
			if haystackLen < k {
				return true
			}

			current := haystack[k]
			if current != needle {
				continue
			}
		}
	}
	return false
}
