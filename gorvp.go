package gorvp

import "github.com/ory-am/fosite/handler/core/strategy"

// TODO move into gorvp struct
var tokenStrategy = &GoRvpStrategy{init: false}

type GoRvpStrategy struct {
	*strategy.RS256JWTStrategy
	init bool
}

func SetTokenStrategy(s *strategy.RS256JWTStrategy) {
	tokenStrategy.RS256JWTStrategy = s
	tokenStrategy.init = true
}

func GetTokenStrategy() (*GoRvpStrategy) {
	if tokenStrategy.init == false {
		// TODO init strategy for one-time use
		panic("Token strategy must set first")
	}
	return tokenStrategy
}
