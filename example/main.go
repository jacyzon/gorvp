package main

import (
	"fmt"
	"github.com/jacyzon/gorvp"
)

func main() {
	config := gorvp.Config{}
	config.Load("../fixtures/backend.json", "../fixtures/scope.json")
	fmt.Println(config.Backend)
	fmt.Println(config.Scope)
	return
}
