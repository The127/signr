package openbao

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/The127/signr"
)

const requestTimeout = 10 * time.Second

// TokenSource answers the current OpenBao token, asked again before every request so a source may renew it.
type TokenSource interface {
	Token() (string, error)
}

// StaticToken is a TokenSource that answers the same token forever.
type StaticToken string

// Token answers the token.
func (token StaticToken) Token() (string, error) {
	return string(token), nil
}

// Config names the OpenBao server, the Transit mount the keys live in, and where the backend's token comes from.
type Config struct {
	Address string
	Mount   string
	Token   TokenSource
}

// Create returns a backend that keeps its keys in the configured Transit mount, refusing a config that lacks one of
// the three.
func (config Config) Create() (signr.Backend, error) {
	if config.Address == "" {
		return nil, errors.New("openbao backend needs an address")
	}

	if config.Mount == "" {
		return nil, errors.New("openbao backend needs a transit mount")
	}

	if config.Token == nil {
		return nil, errors.New("openbao backend needs a token source")
	}

	return &backend{
		transit: transit{
			address: strings.TrimRight(config.Address, "/"),
			mount:   strings.Trim(config.Mount, "/"),
			token:   config.Token.Token,
			client: &http.Client{
				Timeout: requestTimeout,
				// following a redirect would carry the token to wherever it points
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			},
		},
	}, nil
}
