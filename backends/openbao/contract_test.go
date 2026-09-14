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
	s.Backend = s.freshMount()
}

func (s *contract) SetupSubTest() {
	s.Backend = s.freshMount()
}

func (s *contract) freshMount() openbao.Config {
	suffix := make([]byte, 8)
	_, err := rand.Read(suffix)
	s.Require().NoError(err)

	mount := "transit-" + hex.EncodeToString(suffix)

	request, err := http.NewRequest(http.MethodPost, s.address+"/v1/sys/mounts/"+mount, bytes.NewBufferString(`{"type":"transit"}`))
	s.Require().NoError(err)
	request.Header.Set("X-Vault-Token", s.token)

	response, err := http.DefaultClient.Do(request)
	s.Require().NoError(err)
	s.Require().NoError(response.Body.Close())
	s.Require().Equal(http.StatusNoContent, response.StatusCode)

	return openbao.Config{
		Address: s.address,
		Mount:   mount,
		Token:   openbao.StaticToken(s.token),
	}
}

func TestContract(t *testing.T) {
	address := os.Getenv("SIGNR_OPENBAO_ADDR")
	require.NotEmpty(t, address, "SIGNR_OPENBAO_ADDR names the OpenBao the contract runs against")

	token := os.Getenv("SIGNR_OPENBAO_TOKEN")
	require.NotEmpty(t, token, "SIGNR_OPENBAO_TOKEN may mount Transit engines on that OpenBao")

	suite.Run(t, &contract{
		address: address,
		token:   token,
	})
}
