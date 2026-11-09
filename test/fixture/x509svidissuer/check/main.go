package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	socket := flag.String("socket", "unix:///opt/spire/sockets/workload_api.sock", "Workload API address")
	external := flag.Bool("external", false, "Require the fixture issuer")
	renew := flag.Bool("renew", false, "Wait for a renewed SVID")
	successor := flag.Bool("successor", false, "Wait for the prepared successor to issue a leaf")
	tokensOnly := flag.Bool("tokens-only", false, "Verify native JWT issuance independently of external X.509 issuance")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(*socket))
	if err != nil {
		return err
	}
	defer client.Close()
	token, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "issuer-regression"})
	if err != nil {
		return fmt.Errorf("fetch native JWT-SVID: %w", err)
	}
	keys, err := client.FetchJWTBundles(ctx)
	if err != nil {
		return err
	}
	if _, err := jwtsvid.ParseAndValidate(token.Marshal(), keys, []string{"issuer-regression"}); err != nil {
		return fmt.Errorf("verify native JWT-SVID: %w", err)
	}
	if *tokensOnly {
		fmt.Println("verified native JWT-SVID during external issuer outage")
		return nil
	}
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(*socket)))
	if err != nil {
		return err
	}
	defer source.Close()

	var firstSerial string
	for {
		svid, err := source.GetX509SVID()
		if err != nil {
			return err
		}
		if svid.ID.String() != "spiffe://domain.test/workload" {
			return fmt.Errorf("unexpected workload identity: %s", svid.ID)
		}
		if _, _, err := x509svid.Verify(svid.Certificates, source); err != nil {
			return fmt.Errorf("verify delivered chain against delivered bundle: %w", err)
		}
		publicKey, err := x509.MarshalPKIXPublicKey(svid.PrivateKey.Public())
		if err != nil {
			return err
		}
		leaf := svid.Certificates[0]
		if !bytes.Equal(publicKey, leaf.RawSubjectPublicKeyInfo) {
			return errors.New("SVID key does not match leaf")
		}
		if gotExternal := strings.HasPrefix(leaf.Issuer.CommonName, "SPIRE external issuer test root"); gotExternal != *external {
			return fmt.Errorf("unexpected leaf issuer: %s", leaf.Issuer)
		}
		serial := leaf.SerialNumber.String()
		bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
		if err != nil {
			return err
		}
		if *external {
			native, externalRoots := false, 0
			for _, root := range bundle.X509Authorities() {
				if strings.HasPrefix(root.Subject.CommonName, "SPIRE external issuer test root") {
					externalRoots++
				} else {
					native = true
				}
			}
			if !native || externalRoots == 0 {
				return errors.New("bundle must intentionally retain native and external roots")
			}
			if *successor && leaf.Issuer.CommonName == "SPIRE external issuer test root v2" && externalRoots < 2 {
				return errors.New("disjoint rollover must retain both external trust roots")
			}
		}
		if (!*renew || firstSerial != "" && serial != firstSerial) && (!*successor || leaf.Issuer.CommonName == "SPIRE external issuer test root v2") {
			fmt.Printf("verified %s external=%t renewed=%t\n", svid.ID, *external, *renew)
			return nil
		}
		firstSerial = serial
		if err := source.WaitUntilUpdated(ctx); err != nil {
			return fmt.Errorf("wait for renewed SVID: %w", err)
		}
	}
}
