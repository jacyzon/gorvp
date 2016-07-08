package gorvp

import (
	"fmt"
	"net/http"
	"net/url"
	"net/http/httputil"
	"strings"
	"regexp"
)

func ReverseProxyServer(uri string) http.Handler {
	debug("Returning a reverse proxy server for %s.", uri)
	dest, _ := url.Parse(addProtocol(uri))
	return NewSingleHostReverseProxy(dest)
}

func newStaticServer(uri string, hasCustom404 bool, custom404 string) http.Handler {
	debug("Returning a static server for %s", uri)
	return &StaticServer{http.FileServer(http.Dir(uri)), hasCustom404, custom404}
}

func newSingleFileServer(uri string) http.Handler {
	debug("Returning a single file server for %s", uri)
	return &SingleFileServer{uri}
}

func addProtocol(url string) string {
	if matches, _ := regexp.MatchString("^\\w+://", url); !matches {
		return fmt.Sprintf("http://%s", url)
	}

	return url
}

func singleJoiningSlashWithoutTrailing(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	bempty := len(b) == 0
	switch {
	case bempty:
		return a
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func NewSingleHostReverseProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlashWithoutTrailing(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
	}
	return &httputil.ReverseProxy{Director: director}
}
