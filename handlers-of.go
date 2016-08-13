package gorvp

import (
	"fmt"
	"os"
	"regexp"
)

type Handlers map[string]*Handler

func handlerOf(backendDoc Frontend, hasCustom404 bool, custom404 string) *Handler {
	uri := backendDoc.Backend
	debug("Setting up the HTTP handler that will serve %s", uri)

	handler := &Handler{
		isReverseProxy: false,
		isStatic: false,
		uri: uri,
		server: nil,
		scopes: backendDoc.Scopes,
	}
	isStatic := isLocalPath(uri)

	if isStatic && isSingleFile(uri) {
		handler.isStatic = true
		handler.server = newSingleFileServer(uri)
	} else if isStatic {
		handler.isStatic = true
		handler.server = newStaticServer(uri, hasCustom404, custom404)
	} else {
		handler.isReverseProxy = true
		handler.server = ReverseProxyServer(uri)
	}

	return handler
}

func handlersOf(backend map[string]Frontend) Handlers {
	handlers := make(Handlers)

	backendDoc, hasCustom404 := backend["*"]

	custom404 := backendDoc.Backend

	if hasCustom404 {
		hasCustom404 = isLocalPath(custom404)
	}

	if hasCustom404 {
		custom404 = fmt.Sprintf("%s/index.html", custom404)
	}

	for path, backendDoc := range backend {
		handlers[path] = handlerOf(backendDoc, hasCustom404, custom404)
	}

	return handlers
}

func isLocalPath(config string) bool {
	matches, _ := regexp.MatchString("^/", config)
	return matches
}

func isSingleFile(uri string) bool {
	f, err := os.Open(uri)

	if err != nil {
		return false
	}

	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return false
	}

	switch mode := fi.Mode(); {
	case mode.IsDir():
		return false
	case mode.IsRegular():
		return true
	}

	return false
}
