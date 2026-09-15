//go:build openbao

package openbao_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/The127/signr/backends/openbao"
	"github.com/The127/signr/backendtest"
)

type contract struct {
	backendtest.Suite
	address string
	token   string
}

func (s *contract) SetupTest() {
	s.Backend = freshMount(s.Require(), s.address, s.token)
}

func (s *contract) SetupSubTest() {
	s.Backend = freshMount(s.Require(), s.address, s.token)
}

type sealingContract struct {
	backendtest.SealingSuite
	address string
	token   string
}

func (s *sealingContract) SetupTest() {
	s.Backend = freshMount(s.Require(), s.address, s.token)
}

func (s *sealingContract) SetupSubTest() {
	s.Backend = freshMount(s.Require(), s.address, s.token)
}

func freshMount(assertions *require.Assertions, address string, token string) openbao.Config {
	suffix := make([]byte, 8)
	_, err := rand.Read(suffix)
	assertions.NoError(err)

	mount := "transit-" + hex.EncodeToString(suffix)

	request, err := http.NewRequest(http.MethodPost, address+"/v1/sys/mounts/"+mount, bytes.NewBufferString(`{"type":"transit"}`))
	assertions.NoError(err)
	request.Header.Set("X-Vault-Token", token)

	response, err := http.DefaultClient.Do(request)
	assertions.NoError(err)
	assertions.NoError(response.Body.Close())
	assertions.Equal(http.StatusNoContent, response.StatusCode)

	return openbao.Config{
		Address: address,
		Mount:   mount,
		Token:   openbao.StaticToken(token),
	}
}

func openBaoUnderTest(t *testing.T) (string, string) {
	t.Helper()

	address := os.Getenv("SIGNR_OPENBAO_ADDR")
	require.NotEmpty(t, address, "SIGNR_OPENBAO_ADDR names the OpenBao the contract runs against")

	token := os.Getenv("SIGNR_OPENBAO_TOKEN")
	require.NotEmpty(t, token, "SIGNR_OPENBAO_TOKEN may mount Transit engines on that OpenBao")

	return address, token
}

func TestContract(t *testing.T) {
	address, token := openBaoUnderTest(t)

	suite.Run(t, &contract{
		address: address,
		token:   token,
	})
}

func TestSealingContract(t *testing.T) {
	address, token := openBaoUnderTest(t)

	suite.Run(t, &sealingContract{
		address: address,
		token:   token,
	})
}
