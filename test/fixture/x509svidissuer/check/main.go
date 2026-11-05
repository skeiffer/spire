package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

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
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
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
		if gotExternal := leaf.Issuer.CommonName == "SPIRE external issuer test root"; gotExternal != *external {
			return fmt.Errorf("unexpected leaf issuer: %s", leaf.Issuer)
		}
		serial := leaf.SerialNumber.String()
		if !*renew || firstSerial != "" && serial != firstSerial {
			fmt.Printf("verified %s external=%t renewed=%t\n", svid.ID, *external, *renew)
			return nil
		}
		firstSerial = serial
		if err := source.WaitUntilUpdated(ctx); err != nil {
			return fmt.Errorf("wait for renewed SVID: %w", err)
		}
	}
}
