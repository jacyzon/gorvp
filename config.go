package gorvp

import (
	"io/ioutil"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
	"gopkg.in/yaml.v2"
)

type FrontDocument map[string]map[string]Frontend

type DatabaseDocument struct {
	Type       string `yaml:"type"`
	Connection string `yaml:"connection"`
}

type RsaKeyDocument struct {
	Public  string `yaml:"public"`
	Private string `yaml:"private"`
}

type Config struct {
	Frontend FrontDocument    `yaml:"frontend"`
	Database DatabaseDocument `yaml:"database"`
	RsaKey   RsaKeyDocument   `yaml:"rsa_key"`
}

type Frontend struct {
	Backend string       `yaml:"backend"`
	Plugins []string     `yaml:"plugins"`
	Scopes  ConfigScopes `yaml:"scopes"`
}

type ConfigScopes []string

func LoadConfig(configPath string) (config *Config, err error) {
	config = &Config{}
	content, err := ioutil.ReadFile(configPath)

	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(content, config)

	if err != nil {
		return nil, err
	}

	return config, nil
}

func (config *Config) SetupRoute(router *mux.Router, m *negroni.Negroni) {
	for _, frontend := range config.Frontend {
		for path, _ := range frontend {
			router.PathPrefix(path).Handler(m)
		}
	}
}
