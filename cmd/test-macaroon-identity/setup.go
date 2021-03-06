package main

import (
	"log"
	"time"

	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/albertodonato/macaroon-identity/authservice"
	"github.com/albertodonato/macaroon-identity/targetservice"
)

const macaroonValidity = 1 * time.Minute

// Sample user/password credentials.
var sampleCredentials = map[string]string{
	"user1": "pass1",
	"user2": "pass2",
	"user3": "pass3",
}

// Sample user/groups mapping.
var sampleGroups = map[string][]string{
	"user1": {"group1", "group3"},
	"user2": {"group2"},
	"user3": {"group3"},
}

// Groups required by the target service for authenticating a user. A user can
// belong to any of the specified groups.
var requiredGroups = []string{
	"group1",
	"group2",
}

func setupAuthService(logger *log.Logger) *authservice.AuthService {
	s := authservice.New(authservice.AuthServiceParams{
		ListenAddr:       "localhost:0",
		KeyPair:          bakery.MustGenerateKey(),
		MacaroonValidity: macaroonValidity,
		Logger:           logger,
	})
	s.Checker.AddCreds(sampleCredentials)
	s.Checker.AddGroups(sampleGroups)
	if err := s.Start(true); err != nil {
		panic(err)
	}

	return s
}

func setupTargetService(logger *log.Logger, authService *authservice.AuthService, background bool) *targetservice.TargetService {
	t := targetservice.New(targetservice.TargetServiceParams{
		Endpoint:       "localhost:0",
		AuthEndpoint:   authService.Endpoint(),
		AuthKey:        &authService.KeyPair.Public,
		RequiredGroups: requiredGroups,
		Logger:         logger,
	})
	if err := t.Start(background); err != nil {
		panic(err)
	}

	return t
}
