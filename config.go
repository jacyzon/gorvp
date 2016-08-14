package gorvp

import (
	"io/ioutil"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
	"gopkg.in/yaml.v2"
	"crypto/rsa"
	"encoding/pem"
	"crypto/x509"
	"log"
	"crypto/rand"
	"os"
	"path/filepath"
)

type FrontDocument map[string]map[string]Frontend

type DatabaseDocument struct {
	Type       string `yaml:"type"`
	Connection string `yaml:"connection"`
}

type RsaKeyDocument struct {
	Token RsaKey `yaml:"token"`
	Proxy RsaKey `yaml:"proxy"`
}

type RsaKey struct {
	Public  string `yaml:"public"`
	Private string `yaml:"private"`
	Key     *rsa.PrivateKey
}

type Config struct {
	ConfigPath string
	Frontend   FrontDocument    `yaml:"frontend"`
	Database   DatabaseDocument `yaml:"database"`
	RsaKey     RsaKeyDocument   `yaml:"rsa_key"`
}

type Frontend struct {
	Backend string       `yaml:"backend"`
	Plugins []string     `yaml:"plugins"`
	Scopes  ConfigScopes `yaml:"scopes"`
}

type ConfigScopes []string

func (c *Config) Load() (err error) {
	content, err := ioutil.ReadFile(c.ConfigPath)

	if err != nil {
		return err
	}

	err = yaml.Unmarshal(content, c)

	if err != nil {
		return err
	}

	return nil
}

func (config *Config) SetupRoute(router *mux.Router, m *negroni.Negroni) {
	for _, frontend := range config.Frontend {
		for path, _ := range frontend {
			router.PathPrefix(path).Handler(m)
		}
	}
}

func (c *Config) GenerateRsaKeyIfNotExist() {
	generateRsaKeyIfNotExist(&c.RsaKey.Token)
	generateRsaKeyIfNotExist(&c.RsaKey.Proxy)
}

func generateRsaKeyIfNotExist(rsaKey *RsaKey) {
	if _, err := os.Stat(rsaKey.Private); err != nil {
		if os.IsNotExist(err) {
			debug("generate new rsa key")
			key, err := rsa.GenerateKey(rand.Reader, 1152)
			if err != nil {
				panic(err)
			}
			// save RSA key
			rsaKey.Key = key
			priBytes := pem.EncodeToMemory(&pem.Block{
				Type: "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			})
			os.MkdirAll(filepath.Dir(rsaKey.Private), 0755)
			err = ioutil.WriteFile(rsaKey.Private, priBytes, 0600)
			if err != nil {
				log.Fatalf("can not write private key: %s", err)
				panic(err)
			}

			// save RSA public key
			pubASN1, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
			pubBytes := pem.EncodeToMemory(&pem.Block{
				Type: "RSA PUBLIC KEY",
				Bytes: pubASN1,
			})
			os.MkdirAll(filepath.Dir(rsaKey.Public), 0755)
			err = ioutil.WriteFile(rsaKey.Public, pubBytes, 0644)
			if err != nil {
				log.Fatalf("can not write public key: %s", err)
				panic(err)
			}
			return
		}
		panic(err)
	}

	// file exists, read the private key
	pemData, err := ioutil.ReadFile(rsaKey.Private)
	if err != nil {
		log.Fatalf("can not read key file: %s", err)
		if (os.IsNotExist(err)) {
		}
		panic(err)
	}

	// extract the PEM-encoded data block
	pemBlock, _ := pem.Decode(pemData)
	if pemBlock == nil {
		log.Fatalf("bad key data: %s", "not PEM-encoded")
		panic(err)
	}
	if got, want := pemBlock.Type, "RSA PRIVATE KEY"; got != want {
		log.Fatalf("unknown key type %q, want %q", got, want)
		panic(err)
	}

	// decode the RSA private key
	key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		log.Fatalf("bad private key: %s", err)
		panic(err)
	}
	rsaKey.Key = key
}
