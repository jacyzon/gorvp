package gorvp

import (
	"io/ioutil"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

type BackendDocument map[string]map[string]Backend

type Config struct {
	Backend BackendDocument
}

type Backend struct {
	Backend string `json:"backend"`
	Comment string `json:"comment"`
	Plugins []string `json:"plugins"`
	Scopes  ConfigScopes `json:"scopes"`
}

type ConfigScopes []string

func Read(filename string) (BackendDocument, error) {
	backendDoc := make(BackendDocument)
	content, err := ioutil.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(content, &backendDoc)

	if err != nil {
		return nil, err
	}

	return backendDoc, nil
}

func (config *Config) Load(backendConfigPath string) {
	raw, _ := Read(backendConfigPath)
	config.Backend = raw
}

func (config *Config) SetupRoute(router *mux.Router, m *negroni.Negroni) {
	for _, backend := range config.Backend {
		for path, _ := range backend {
			router.PathPrefix(path).Handler(m)
		}
	}
}
