package gorvp

import (
	"net/http"
)

type Handler struct {
	isReverseProxy bool
	isStatic       bool
	uri            string
	server         http.Handler
	scopes         ConfigScopes
}
