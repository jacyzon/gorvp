package gorvp

type Sites map[string]Handlers

var sites Sites

func SetupSites(config *Config) {
	newSites := make(Sites)

	for hostname, frontend := range config.Frontend {
		debug("Setting up %s", hostname)
		newSites[hostname] = handlersOf(frontend)
	}

	sites = newSites
}
