package main

import (
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/urfave/cli"
	"os"
	"github.com/jacyzon/gorvp/example/ident"
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
		router := mux.NewRouter()
		goRvp := &gorvp.GoRvp{
			Router: router,
			Config: config,
		}

		identityProvider := &ident.IdentityProvider{
			SharedSecret: []byte("a1z5iJ0o4MN8UnbLBJwTGH1NxVZYW8EO"),
		}
		router.HandleFunc("/ident", identityProvider.ServeHTTP)
		return goRvp.Run()
	}
	app.Run(os.Args)
}
