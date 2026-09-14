package openbao_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr"
	"github.com/The127/signr/backends/openbao"
)

func printedEveryWay(values ...any) string {
	printed := ""
	for _, value := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%t", "%d"} {
			printed += fmt.Sprintf(verb, value) + "\n"
		}
	}

	return printed
}

func TestNothingTheBackendHandsOutPrintsTheOpenBaoToken(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       ed25519TransitKey(t),
	})
	config.Token = openbao.StaticToken("hvs.never-printed")
	manager, err := signr.New(signr.Config{Backend: config})
	require.NoError(t, err)
	group := manager.GetGroup("signing")
	key, err := group.GetKey("EdDSA")
	require.NoError(t, err)
	signer, err := key.Signer()
	require.NoError(t, err)

	// act
	printed := printedEveryWay(manager, group, key, signer)

	// assert
	assert.NotContains(t, printed, "hvs.never-printed")
}
