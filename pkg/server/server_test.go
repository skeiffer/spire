package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/x509svidissuer"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakehealthchecker"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeserverkeymanager"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/suite"
)

type ServerTestSuite struct {
	suite.Suite
	server *Server
	ds     *fakedatastore.DataStore
	stdout *bytes.Buffer
}

func (suite *ServerTestSuite) SetupTest() {
	suite.ds = fakedatastore.New(suite.T())

	suite.stdout = new(bytes.Buffer)
	logrusLevel, err := logrus.ParseLevel("DEBUG")
	suite.Nil(err)

	logger := logrus.New()
	logger.Out = suite.stdout
	logger.Level = logrusLevel

	suite.server = New(Config{
		Log:         logger,
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	})
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

func (suite *ServerTestSuite) TestExternalHostWaitsForNativeCAInitialization() {
	t := suite.T()
	suite.server.config.DataDir = t.TempDir()
	suite.server.config.CAKeyType = keymanager.ECP256
	suite.server.config.JWTKeyType = keymanager.ECP256
	suite.server.config.WITKeyType = keymanager.ECP256
	cat := fakeservercatalog.New()
	cat.SetDataStore(suite.ds)
	cat.SetKeyManager(fakeserverkeymanager.New(t))
	authority, _ := testca.CreateCACertificate(t, nil, nil, testca.WithKeyUsage(x509.KeyUsageCertSign))
	plugin := &startupIssuer{root: authority}
	cat.SetX509SVIDIssuer(plugin)
	checker := fakehealthchecker.New()
	builder, err := suite.server.newCredBuilder(cat)
	suite.Require().NoError(err)
	validator, err := suite.server.newCredValidator()
	suite.Require().NoError(err)
	var publish x509svidissuer.PublishAuthoritiesFunc
	host := suite.server.newX509SVIDIssuer(cat, checker, func(ctx context.Context, roots []*x509.Certificate) error {
		suite.Require().NotNil(publish, "host must not publish before the native manager exists")
		return publish(ctx, roots)
	})
	defer host.Close()
	suite.Zero(plugin.subscriptions.Load(), "construction must not subscribe or start the host")
	serverCA := suite.server.newCA(telemetry.Blackhole{}, builder, validator, checker, host)
	manager, err := suite.server.newCAManager(t.Context(), cat, telemetry.Blackhole{}, serverCA, builder, validator)
	suite.Require().NoError(err)
	defer manager.Close()
	_, err = suite.server.newCASync(t.Context(), checker, manager)
	suite.Require().NoError(err)
	publish = manager.PublishX509Authorities
	suite.Require().NotNil(serverCA.X509CA())
	suite.Require().NotNil(serverCA.JWTKey())
	suite.Require().NotNil(serverCA.WITKey())
	suite.Require().NoError(host.Initialize(t.Context()))
	suite.True(host.CheckHealth().Ready)
	host.Close()
	suite.False(host.CheckHealth().Ready)
}

type startupIssuer struct {
	root          *x509.Certificate
	subscriptions atomic.Int32
}

func (*startupIssuer) Name() string     { return "startup-test" }
func (*startupIssuer) Type() string     { return "X509SVIDIssuer" }
func (*startupIssuer) Version() string  { return "v1" }
func (*startupIssuer) IsExternal() bool { return false }
func (*startupIssuer) IssueX509SVID(context.Context, *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
	return nil, errors.New("unexpected issuance during authority initialization")
}
func (p *startupIssuer) SubscribeAuthoritySnapshots(ctx context.Context) (x509svidissuer.AuthoritySnapshotStream, error) {
	p.subscriptions.Add(1)
	return &startupAuthorityStream{ctx: ctx, root: p.root}, nil
}

type startupAuthorityStream struct {
	ctx  context.Context
	root *x509.Certificate
}

func (s *startupAuthorityStream) Recv() (*issuerv1.AuthoritySnapshot, error) {
	if s.root != nil {
		root := s.root
		s.root = nil
		return &issuerv1.AuthoritySnapshot{AuthorityVersion: "v1", AuthorityChains: []*issuerv1.AuthorityChain{{Root: root.Raw}}}, nil
	}
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}

func (suite *ServerTestSuite) TestValidateTrustDomain() {
	ctx := context.Background()
	ds := suite.ds

	// Create default trust domain
	trustDomain, err := spiffeid.TrustDomainFromString("spiffe://test.com")
	suite.NoError(err)

	// Create new trust domain
	newTrustDomain, err := spiffeid.TrustDomainFromString("spiffe://new_test.com")
	suite.NoError(err)

	// Set trust domain to server
	suite.server.config.TrustDomain = trustDomain
	suite.NoError(err)

	// No attested nodes, not error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)

	// create attested node with current trust domain
	attestedNode, err := ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:            "spiffe://test.com/host",
		AttestationDataType: "fake_nodeattestor_1",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
		CertSerialNumber:    "18392437442709699290",
	})
	suite.NoError(err)

	// Validate created trust domain, no error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)

	// Update server trust domain to force errors
	suite.server.config.TrustDomain = newTrustDomain

	// Validate new trust domain
	err = suite.server.validateTrustDomain(ctx, ds)
	// no error expected, warning is displaying in this case
	suite.NoError(err)
	suite.Require().Contains(suite.stdout.String(), fmt.Sprintf(invalidTrustDomainAttestedNode, "test.com", "new_test.com"))

	// Restore original trust domain
	suite.server.config.TrustDomain = trustDomain

	// Create a registration entry with original trust domain
	registrationEntry, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId:  "spiffe://test.com/foo",
		Selectors: []*common.Selector{{Type: "TYPE", Value: "VALUE"}},
	})
	suite.NoError(err)

	// Attested node and registration entry have the same trust domain as server, no error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)

	// Update server's trust domain, error expected because invalid trust domain
	suite.server.config.TrustDomain = newTrustDomain
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.EqualError(err, fmt.Sprintf(invalidTrustDomainRegistrationEntry, "test.com", "new_test.com"))

	// Create a registration entry with an invalid url
	_, err = ds.DeleteRegistrationEntry(ctx, registrationEntry.EntryId)
	suite.NoError(err)
	suite.server.config.TrustDomain = trustDomain
	registrationEntry, err = ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId:  "spiffe://inv%ild/test",
		Selectors: []*common.Selector{{Type: "TYPE", Value: "VALUE"}},
	})
	suite.NoError(err)
	err = suite.server.validateTrustDomain(ctx, ds)
	expectedError := fmt.Sprintf(invalidSpiffeIDRegistrationEntry, registrationEntry.EntryId, "")
	if suite.Error(err) {
		suite.Contains(err.Error(), expectedError)
	}

	// remove entry to solve error
	_, err = ds.DeleteRegistrationEntry(ctx, registrationEntry.EntryId)
	suite.NoError(err)

	// create attested node with current trust domain
	// drop resp
	_, err = ds.DeleteAttestedNode(ctx, attestedNode.SpiffeId)
	suite.NoError(err)
	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:            "spiffe://inv%ild/host",
		AttestationDataType: "fake_nodeattestor_1",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
		CertSerialNumber:    "18392437442709699290",
	})
	suite.NoError(err)
	// Attested now with same trust domain created, no error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)
	suite.Require().Contains(suite.stdout.String(), invalidSpiffeIDAttestedNode)
}
