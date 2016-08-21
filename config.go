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
	"github.com/go-errors/errors"
	"time"
)

type FrontDocument map[string]map[string]Frontend

type DatabaseDocument struct {
	Type       string `yaml:"type"`
	Connection string `yaml:"connection"`
}

type RsaKeyDocument struct {
	Token    RsaKey `yaml:"token"`
	Internal RsaKey `yaml:"internal"`
}

type RsaKey struct {
	Public  string `yaml:"public"`
	Private string `yaml:"private"`
	Key     *rsa.PrivateKey
}

type LifespanConf struct {
	// second
	AccessToken   time.Duration `yaml:"access_token"`
	RefreshToken  time.Duration `yaml:"refresh_token"`
	AuthorizeCode time.Duration `yaml:"authorization_code"`
}

type TrustedClient struct {
	ID               string
	Name             string `yaml:"name"`
	Scopes           Scopes `yaml:"scopes"`
	Secret           string `yaml:"secret"`
	IdentityEndpoint string `yaml:"identity_endpoint"`
	TokenMountPoint  string `yaml:"token_mount_point"`
	Default_provider bool   `yaml:"default_provider"`
}

type Config struct {
	ConfigPath            string
	Port                  string
	Lifespan              LifespanConf     `yaml:"lifespan"`
	Frontend              FrontDocument    `yaml:"frontend"`
	Database              DatabaseDocument `yaml:"database"`
	RsaKey                RsaKeyDocument   `yaml:"rsa_key"`
	Oauth2AuthMountPoint  string           `yaml:"oauth2_auth_mount_point"`
	Oauth2TokenMountPoint string           `yaml:"oauth2_token_mount_point"`
	TrustedClients        []TrustedClient  `yaml:"trusted_clients"`
}

type Frontend struct {
	Backend string       `yaml:"backend"`
	Plugins []string     `yaml:"plugins"`
	Scopes  ConfigScopes `yaml:"scopes"`
}

type ConfigScopes []string

func (c *Config) Load() (err error) {
	if _, err := os.Stat(c.ConfigPath); err != nil {
		if os.IsNotExist(err) {
			return errors.New("config file not exist.")
		}
	}
	content, err := ioutil.ReadFile(c.ConfigPath)

	if err != nil {
		return errors.New("cannot read the config file.")
	}

	err = yaml.Unmarshal(content, c)

	if err != nil {
		return errors.New("error when parse the file.")
	}
	c.GenerateRsaKeyIfNotExist()
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
	generateRsaKeyIfNotExist(&c.RsaKey.Internal)
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
