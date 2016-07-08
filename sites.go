package gorvp

type Sites map[string]Handlers

var sites Sites

func SetupSites(config *Config) {
	newSites := make(Sites)

	for hostname, backend := range config.Backend {
		debug("Setting up %s", hostname)
		newSites[hostname] = handlersOf(backend)
	}

	sites = newSites
}
