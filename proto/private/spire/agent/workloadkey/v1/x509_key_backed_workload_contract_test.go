package workloadkeyv1_test

import (
	"testing"

	workloadkeyv1 "github.com/spiffe/spire/proto/private/spire/agent/workloadkey/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestGeneratedExperimentalV1APIHasNoPrivateKeyField(t *testing.T) {
	require.Equal(t,
		"/spire.agent.workloadkey.v1.X509KeyBackedWorkloadAPI/FetchX509SVIDs",
		workloadkeyv1.X509KeyBackedWorkloadAPI_FetchX509SVIDs_FullMethodName)
	require.Equal(t,
		"/spire.agent.workloadkey.v1.X509KeyBackedWorkloadAPI/Sign",
		workloadkeyv1.X509KeyBackedWorkloadAPI_Sign_FullMethodName)
	require.Equal(t, int32(1), int32(workloadkeyv1.ProtocolVersion_PROTOCOL_VERSION_V1))

	fields := (&workloadkeyv1.X509KeyBackedSVID{}).ProtoReflect().Descriptor().Fields()
	for _, required := range []protoreflect.Name{"spiffe_id", "x509_svid", "bundle", "key"} {
		require.NotNil(t, fields.ByName(required))
	}
	for _, forbidden := range []protoreflect.Name{"private_key", "x509_svid_key", "pkcs8", "pfx"} {
		require.Nil(t, fields.ByName(forbidden))
	}
}
