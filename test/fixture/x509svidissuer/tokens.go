package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"google.golang.org/protobuf/encoding/protojson"
)

func verifyTokens() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		return serverCommand(ctx, args...).Output()
	}
	bundle, err := run("bundle", "show", "-format", "spiffe")
	if err != nil {
		return err
	}
	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(bundle, &keys); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, kind := range []string{"jwt", "wit"} {
		args := []string{kind, "mint", "-spiffeID", "spiffe://domain.test/token-check", "-ttl", "30s", "-output", "json"}
		if kind == "jwt" {
			args = append(args, "-audience", "external-fixture")
		}
		out, err := run(args...)
		if err != nil {
			return err
		}
		var response struct {
			SVID struct {
				Token string `json:"token"`
			} `json:"svid"`
		}
		if err := json.Unmarshal(out, &response); err != nil {
			return err
		}
		token := response.SVID.Token
		signed, err := jwt.ParseSigned(strings.TrimSpace(token), jwtsvid.AllowedSignatureAlgorithms)
		if err != nil {
			return err
		}
		if len(signed.Headers) != 1 || seen[signed.Headers[0].KeyID] {
			return errors.New("token authorities are not independently identified")
		}
		keyID := signed.Headers[0].KeyID
		seen[keyID] = true
		matching := keys.Key(keyID)
		if len(matching) != 1 || matching[0].Use != kind+"-svid" {
			return errors.New("published token verification key is missing or has the wrong role")
		}
		var claims jwt.Claims
		if err := signed.Claims(matching[0].Key, &claims); err != nil {
			return err
		}
		expected := jwt.Expected{Subject: "spiffe://domain.test/token-check", Time: time.Now()}
		if kind == "jwt" {
			expected.AnyAudience = jwt.Audience{"external-fixture"}
		}
		if err := claims.Validate(expected); err != nil {
			return err
		}
	}
	return nil
}

func rotateJWT() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	raw, err := serverCommand(ctx, "localauthority", "jwt", "prepare", "-output", "json").Output()
	if err != nil {
		return err
	}
	var response localauthorityv1.PrepareJWTAuthorityResponse
	if err := protojson.Unmarshal(raw, &response); err != nil {
		return err
	}
	id := response.GetPreparedAuthority().GetAuthorityId()
	if id == "" {
		return errors.New("prepared JWT authority has no identity")
	}
	return serverCommand(ctx, "localauthority", "jwt", "activate", "-authorityID", id).Run()
}

func verifyOIDC() error {
	client := &http.Client{Timeout: 5 * time.Second}
	discovery, err := client.Get("http://oidc:8080/.well-known/openid-configuration")
	if err != nil {
		return err
	}
	defer discovery.Body.Close()
	if discovery.StatusCode != http.StatusOK {
		return errors.New("OIDC discovery is not ready")
	}
	var config struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(discovery.Body, 64<<10)).Decode(&config); err != nil {
		return err
	}
	if config.JWKSURI != "http://oidc:8080/keys" {
		return errors.New("OIDC discovery returned an unexpected JWKS endpoint")
	}
	response, err := client.Get(config.JWKSURI)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var keys jose.JSONWebKeySet
	if response.StatusCode != http.StatusOK {
		return errors.New("OIDC JWKS is not ready")
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&keys); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := serverCommand(ctx, "jwt", "mint",
		"-spiffeID", "spiffe://domain.test/oidc-check", "-audience", "oidc-check", "-ttl", "30s").Output()
	if err != nil {
		return err
	}

	token, err := jwt.ParseSigned(strings.TrimSpace(string(out)), jwtsvid.AllowedSignatureAlgorithms)
	if err != nil || len(token.Headers) != 1 {
		return errors.New("invalid OIDC verification token")
	}
	matching := keys.Key(token.Headers[0].KeyID)
	if len(matching) != 1 {
		return errors.New("current JWT authority has not propagated to OIDC JWKS")
	}
	var claims jwt.Claims
	if err := token.Claims(matching[0].Key, &claims); err != nil {
		return err
	}
	return claims.Validate(jwt.Expected{
		Subject: "spiffe://domain.test/oidc-check", AnyAudience: jwt.Audience{"oidc-check"}, Time: time.Now(),
	})
}
