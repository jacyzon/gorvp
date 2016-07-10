package gorvp

import (
	"fmt"
	"net/http"
	"strings"
)

func matchingHandlerOf(url, hostname string, handlers Handlers) (result http.Handler, found bool, scopes ConfigScopes) {

	if handlers == nil {
		return nil, false, nil
	}

	for pattern, handler := range handlers {
		debug("Iterating patterns: %s", pattern)

		if pattern == "*" {
			continue
		}

		if len(url) >= len(pattern) && url[0:len(pattern)] == pattern {
			debug("Matched %s%s with the handler attached to %s.", hostname, url, pattern)
			found = true
			result = http.StripPrefix(pattern, handler.server)
			scopes = handler.scopes
		}
	}

	if handler, hasDefaultHandler := handlers["*"]; !found && hasDefaultHandler {
		debug("Matched %s%s with default handler.", hostname, url)
		found = true
		result = handler.server
		scopes = handler.scopes
	}

	return result, found, scopes
}

func matchingServerOf(host, url string) (result http.Handler, found bool, scopes ConfigScopes) {

	hostname := hostnameOf(host)
	wildcard := wildcardOf(hostname)

	result, found, scopes = matchingHandlerOf(url, hostname, sites[hostname])

	if !found {
		if _, hasWildcard := sites[wildcard]; hasWildcard {
			debug("Matching the wildcard %s", wildcard)
			result, found, scopes = matchingHandlerOf(url, hostname, sites[wildcard])
		} else {
			debug("Nothing attached to %s or %s", hostname, wildcard)
		}
	}

	if wildcardSite, hasWildcardSite := sites["*"]; !found && hasWildcardSite {
		debug("No site binded to %s. Falling back to '*' entry.", hostname)
		result, found, scopes = matchingHandlerOf(url, hostname, wildcardSite)
	} else if !found {
		debug("Unable to find any matching site for %s", hostname)
	} else {
		debug("Returning matching site for %s%s.", hostname, url)
	}

	return result, found, scopes
}

func hostnameOf(host string) string {
	hostname := strings.Split(host, ":")[0]

	if len(hostname) > 4 && hostname[0:4] == "www." {
		hostname = hostname[4:]
	}

	return hostname
}

func wildcardOf(hostname string) string {
	parts := strings.Split(hostname, ".")

	if len(parts) < 3 {
		return fmt.Sprintf("*.%s", hostname)
	}

	parts[0] = "*"
	return strings.Join(parts, ".")

}