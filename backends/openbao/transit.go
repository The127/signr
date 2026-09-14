package openbao

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const maxResponseBytes = 1 << 20

var errNotFound = errors.New("openbao has nothing at that path")

type transit struct {
	address string
	mount   string
	token   TokenSource
	client  *http.Client
}

type transitKey struct {
	Type                 string                       `json:"type"`
	LatestVersion        int                          `json:"latest_version"`
	MinDecryptionVersion int                          `json:"min_decryption_version"`
	Keys                 map[string]transitKeyVersion `json:"keys"`
}

type transitKeyVersion struct {
	PublicKey string `json:"public_key"`
}

type keyResponse struct {
	Data transitKey `json:"data"`
}

type createKeyRequest struct {
	Type string `json:"type"`
}

type signRequest struct {
	Input              string `json:"input"`
	KeyVersion         int    `json:"key_version"`
	Prehashed          bool   `json:"prehashed,omitempty"`
	HashAlgorithm      string `json:"hash_algorithm,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
}

type signResponse struct {
	Data struct {
		Signature string `json:"signature"`
	} `json:"data"`
}

func (transit transit) createKey(name string, keyType string) (transitKey, error) {
	status, raw, err := transit.post("keys/"+name, createKeyRequest{
		Type: keyType,
	})
	if err != nil {
		return transitKey{}, err
	}

	var response keyResponse

	err = decode(status, raw, &response)
	if err != nil {
		return transitKey{}, fmt.Errorf("creating transit key %s: %w", name, err)
	}

	return response.Data, nil
}

func (transit transit) readKey(name string) (transitKey, bool, error) {
	status, raw, err := transit.get("keys/" + name)
	if err != nil {
		return transitKey{}, false, err
	}

	var response keyResponse

	err = decode(status, raw, &response)
	if errors.Is(err, errNotFound) {
		return transitKey{}, false, nil
	}

	if err != nil {
		return transitKey{}, false, fmt.Errorf("reading transit key %s: %w", name, err)
	}

	return response.Data, true, nil
}

func (transit transit) sign(name string, request signRequest) (signResponse, error) {
	status, raw, err := transit.post("sign/"+name, request)
	if err != nil {
		return signResponse{}, err
	}

	var response signResponse

	err = decode(status, raw, &response)
	if err != nil {
		return signResponse{}, fmt.Errorf("signing with transit key %s: %w", name, err)
	}

	return response, nil
}

func (transit transit) get(path string) (int, []byte, error) {
	request, err := http.NewRequest(http.MethodGet, transit.url(path), http.NoBody)
	if err != nil {
		return 0, nil, fmt.Errorf("building openbao request: %w", err)
	}

	return transit.do(request)
}

func (transit transit) post(path string, body any) (int, []byte, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, nil, fmt.Errorf("encoding openbao request: %w", err)
	}

	request, err := http.NewRequest(http.MethodPost, transit.url(path), bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, fmt.Errorf("building openbao request: %w", err)
	}

	request.Header.Set("Content-Type", "application/json")

	return transit.do(request)
}

func (transit transit) do(request *http.Request) (int, []byte, error) {
	token, err := transit.token.Token()
	if err != nil {
		return 0, nil, fmt.Errorf("getting the openbao token: %w", err)
	}

	request.Header.Set("X-Vault-Token", token)

	response, err := transit.client.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("asking openbao: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, fmt.Errorf("reading openbao response: %w", err)
	}

	return response.StatusCode, raw, nil
}

func (transit transit) url(path string) string {
	return transit.address + "/v1/" + transit.mount + "/" + path
}

// OpenBao puts its refusal into an errors list with a 4xx status, answers
// a missing key with a 404 and an empty list, and other failures with a
// status and little else. A 404 for a missing mount carries an error, a
// 404 without the list did not come from OpenBao's key handler.
func decode(status int, raw []byte, into any) error {
	var refusal struct {
		Errors *[]string `json:"errors"`
	}

	if len(raw) > 0 {
		err := json.Unmarshal(raw, &refusal)
		if err != nil {
			return fmt.Errorf("openbao answered %d with an unreadable body: %w", status, err)
		}
	}

	if refusal.Errors != nil {
		if len(*refusal.Errors) > 0 {
			return fmt.Errorf("openbao refused: %s", strings.Join(*refusal.Errors, ", "))
		}

		if status == http.StatusNotFound {
			return errNotFound
		}
	}

	if status != http.StatusOK {
		return fmt.Errorf("openbao answered %d", status)
	}

	err := json.Unmarshal(raw, into)
	if err != nil {
		return fmt.Errorf("openbao answered with an unreadable body: %w", err)
	}

	return nil
}

func (key transitKey) publicKey(keyType string, version int) (crypto.PublicKey, error) {
	if key.Type != keyType {
		return nil, fmt.Errorf("transit holds it as %s, not %s", key.Type, keyType)
	}

	keyVersion, found := key.Keys[strconv.Itoa(version)]
	if !found {
		return nil, fmt.Errorf("no version %d", version)
	}

	return parsePublicKey(keyType, keyVersion.PublicKey)
}

func parsePublicKey(keyType string, encoded string) (crypto.PublicKey, error) {
	switch keyType {
	case "ed25519":
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decoding ed25519 public key: %w", err)
		}

		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("ed25519 public key is %d bytes, not %d", len(raw), ed25519.PublicKeySize)
		}

		return ed25519.PublicKey(raw), nil

	case "rsa-4096":
		block, _ := pem.Decode([]byte(encoded))
		if block == nil {
			return nil, fmt.Errorf("rsa public key is not pem")
		}

		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("rsa public key is a pem %q block, not a public key", block.Type)
		}

		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing rsa public key: %w", err)
		}

		rsaKey, isRSA := parsed.(*rsa.PublicKey)
		if !isRSA {
			return nil, fmt.Errorf("rsa public key parses as %T", parsed)
		}

		if rsaKey.N.BitLen() != 4096 {
			return nil, fmt.Errorf("rsa-4096 public key is %d bits", rsaKey.N.BitLen())
		}

		return rsaKey, nil

	default:
		return nil, fmt.Errorf("unsupported transit key type %q", keyType)
	}
}
