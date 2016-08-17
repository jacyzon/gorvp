package main

import (
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/urfave/cli"
	"os"
	"github.com/jacyzon/gorvp/example/ident"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/ory-am/fosite/handler/oauth2"
	"github.com/jacyzon/gorvp"
	"github.com/gorilla/mux"
)

func main() {
	config := &gorvp.Config{}

	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "config,c",
			Value:       "config.yaml",
			Usage:       "config path",
			Destination: &config.ConfigPath,
		},
		cli.StringFlag{
			Name:        "port,p",
			Value:       "3000",
			Usage:       "port number to listen on",
			Destination: &config.Port,
		},
	}

	app.Action = func(c *cli.Context) error {
		config.Load()

		identityProvider := &ident.IdentityProvider{
			JWTStrategy: &oauth2.RS256JWTStrategy{
				RS256JWTStrategy: &jwt.RS256JWTStrategy{
					// TODO only public key is needed
					PrivateKey: config.RsaKey.Internal.Key,
				},
			},
		}
		router := mux.NewRouter()
		router.HandleFunc("/ident", identityProvider.ServeHTTP)
		goRvp := &gorvp.GoRvp{
			Router: router,
			Config: config,
		}
		return goRvp.Run()
	}
	app.Run(os.Args)
}
