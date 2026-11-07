package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func command(args []string) error {
	if len(args) == 0 {
		return errors.New("fixture command is required")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	root := flags.String("root", "/test", "isolated process-test root")
	version := flags.String("version", "v1", "immutable authority version")
	streamError := flags.Bool("stream-error", false, "interrupt authority subscriptions")
	rejectIssue := flags.Bool("reject-issue", false, "reject leaf issuance")
	shortTTL := flags.Int64("short-ttl", 0, "shorten fixture leaf lifetime in seconds")
	bootstrapDependent := flags.Bool("bootstrap-dependent", false, "require IdentityProvider before issuer bootstrap")
	publishedAgo := flags.Int64("published-ago", 0, "backdate authority publication in seconds")
	instance := flags.String("instance", "server1", "server instance")
	joinToken := flags.String("token", "", "Agent join token")
	server := flags.String("server", "server1", "server DNS name")
	bundle := flags.String("bundle", "", "bundle PEM to check against external authorities")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "prepare":
		return prepare(*root)
	case "control":
		return writeJSON(filepath.Join(*root, "provider", "controls.json"), controls{
			Version: *version, StreamError: *streamError, RejectIssue: *rejectIssue, ShortTTL: *shortTTL,
			BootstrapDependent: *bootstrapDependent, PublishedAgo: *publishedAgo,
		})
	case "check":
		return check(*root, *instance)
	case "agent-config":
		return agentConfig(*root, *instance, *server, *joinToken)
	case "check-bundle":
		return checkBundle(*root, *bundle)
	case "verify-tokens":
		return verifyTokens()
	case "verify-oidc":
		return verifyOIDC()
	case "rotate-jwt":
		return rotateJWT()
	default:
		return errors.New("unknown fixture command")
	}
}

func prepare(root string) error {
	if !filepath.IsAbs(root) {
		return errors.New("fixture root must be absolute")
	}
	for _, dir := range []string{"provider", "shared", "conf", "keys/server1", "keys/server2", "run/server1", "run/server2"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0700); err != nil {
			return err
		}
	}
	if _, err := loadMaterial(filepath.Join(root, "provider")); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(root, "provider", "controls.json"), controls{
		Version: "v1", PublishedAgo: int64((119*time.Hour + 54*time.Minute) / time.Second),
	}); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(binary)
	for _, instance := range []string{"server1", "server2"} {
		configText := fmt.Sprintf(`server {
    bind_address = "0.0.0.0"
    bind_port = "8081"
    trust_domain = "domain.test"
    data_dir = %q
    socket_path = %q
    default_x509_svid_ttl = "30s"
    agent_ttl = "30s"
    ca_ttl = "1h"
    log_level = "DEBUG"
    experimental {
        enable_wit_svids = true
        default_wit_svid_ttl = "30s"
    }
}
plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = %q
        }
    }
    KeyManager "disk" {
        plugin_data { keys_path = %q }
    }
    NodeAttestor "join_token" { }
    X509SVIDIssuer "fixture" {
        plugin_cmd = %q
        plugin_checksum = %q
        plugin_data { dir = %q }
    }
}
`, filepath.Join(root, "data", instance), filepath.Join(root, "run", instance, "api.sock"),
			filepath.Join(root, "shared", "datastore.sqlite3"), filepath.Join(root, "keys", instance, "keys.json"),
			executable, hex.EncodeToString(checksum[:]), filepath.Join(root, "provider"))
		if err := os.WriteFile(filepath.Join(root, "conf", instance+".conf"), []byte(configText), 0600); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(root, "conf", "oidc.conf"), []byte(fmt.Sprintf(`domains = ["oidc"]
insecure_addr = ":8080"
allow_insecure_scheme = true
server_api {
    address = %q
    poll_interval = "1s"
}
`, "unix://"+filepath.Join(root, "run", "server1", "api.sock"))), 0600)
}

func check(root, instance string) error {
	var keys struct {
		Keys map[string]json.RawMessage `json:"keys"`
	}
	if err := readJSON(filepath.Join(root, "keys", instance, "keys.json"), &keys); err != nil {
		return err
	}
	if len(keys.Keys) == 0 {
		return errors.New("no token keys were generated")
	}
	for keyID := range keys.Keys {
		if !strings.HasPrefix(keyID, "token-authority-") {
			return errors.New("non-token KeyManager role was used in external mode")
		}
	}
	return nil
}

func agentConfig(root, instance, server, token string) error {
	if token == "" || instance == "" || filepath.Base(instance) != instance {
		return errors.New("agent instance and token are required")
	}
	material, err := loadMaterial(filepath.Join(root, "provider"))
	if err != nil {
		return err
	}
	bundlePath := filepath.Join(root, "conf", instance+"-bundle.pem")
	if err := os.WriteFile(bundlePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: material["v1"].Root}), 0600); err != nil {
		return err
	}
	text := fmt.Sprintf(`agent {
    data_dir = %q
    log_level = "DEBUG"
    server_address = %q
    server_port = "8081"
    trust_bundle_path = %q
    trust_domain = "domain.test"
    join_token = %q
}
plugins {
    NodeAttestor "join_token" { }
    KeyManager "memory" { }
    WorkloadAttestor "unix" { }
}
`, filepath.Join(root, "data", instance), server, bundlePath, token)
	return os.WriteFile(filepath.Join(root, "conf", instance+".conf"), []byte(text), 0600)
}

func checkBundle(root, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	material, err := loadMaterial(filepath.Join(root, "provider"))
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for len(raw) != 0 {
		block, rest := pem.Decode(raw)
		if block == nil {
			return errors.New("malformed external bundle")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		if !cert.IsCA {
			return errors.New("bundle contains a non-CA certificate")
		}
		found := false
		for version, authority := range material {
			if string(cert.Raw) == string(authority.Root) {
				seen[version], found = true, true
			}
		}
		if !found {
			return errors.New("bundle contains a root not issued by the external fixture")
		}
		raw = rest
	}
	if !seen["v1"] || !seen["v2"] {
		return errors.New("staged external trust has not propagated")
	}
	return nil
}
