package gorvp

import (
	"io/ioutil"
	"encoding/json"
	"reflect"
)

type (
	BackendDocument map[string]map[string]map[string]string
	ScopeDocument map[string][]string
	RawDocument map[string]interface{}
)

type Config struct {
	Backend BackendDocument
	Scope   ScopeDocument
}

func Read(filename string) (RawDocument, error) {
	raw := make(RawDocument)
	content, err := ioutil.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(content, &raw)

	if err != nil {
		return nil, err
	}

	return raw, nil
}

func NormalizeBackend(raw RawDocument) BackendDocument {
	config := make(BackendDocument)

	for hostname, options := range raw {
		switch t := options.(type) {
		case string:
			config[hostname] = make(map[string]map[string]string)
			config[hostname]["/"] = make(map[string]string)
			config[hostname]["/"]["backend"] = t
			break
		case map[string]interface{}:
			config[hostname] = make(map[string]map[string]string)
			for path, v := range t {
				config[hostname][path] = make(map[string]string)
				for kk, vv := range v.(map[string]interface{}) {
					switch tt := vv.(type) {
					case string:
						config[hostname][path][kk] = tt
						break
					}
				}
			}
			break
		}
	}

	return config
}

func NormalizeScope(raw RawDocument) ScopeDocument {
	config := make(ScopeDocument)

	for scope, urlList := range raw {
		switch reflect.TypeOf(urlList).Kind() {
		case reflect.Slice:
			s := reflect.ValueOf(urlList)
			config[scope] = make([]string, s.Len())
			for i := 0; i < s.Len(); i++ {
				config[scope][i] = s.Index(i).Interface().(string)
			}
		}
	}

	return config
}

func (config *Config) Load(backendConfigPath string, scopeConfigPath string) {
	raw, _ := Read(backendConfigPath)
	config.Backend = NormalizeBackend(raw)
	raw, _ = Read(scopeConfigPath)
	config.Scope = NormalizeScope(raw)
}