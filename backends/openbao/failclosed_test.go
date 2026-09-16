package openbao_test

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/The127/signr"
	"github.com/The127/signr/backends/openbao"
	"github.com/The127/signr/backendtest"
)

type transitAnswers struct {
	keyStatus int
	key       string
	signature string
	plaintext string
	onDecrypt func(ciphertext string)
}

func fakeTransit(t *testing.T, answers transitAnswers) openbao.Config {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sign/") {
			_, err := w.Write([]byte(`{"data":{"signature":"` + answers.signature + `"}}`))
			assert.NoError(t, err)

			return
		}

		if strings.Contains(r.URL.Path, "/decrypt/") {
			if answers.onDecrypt != nil {
				var request struct {
					Ciphertext string `json:"ciphertext"`
				}

				assert.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				answers.onDecrypt(request.Ciphertext)
			}

			_, err := w.Write([]byte(`{"data":{"plaintext":"` + answers.plaintext + `"}}`))
			assert.NoError(t, err)

			return
		}

		w.WriteHeader(answers.keyStatus)
		_, err := w.Write([]byte(answers.key))
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	return openbao.Config{
		Address: server.URL,
		Mount:   "transit",
		Token:   openbao.StaticToken("token"),
	}
}

func transitKey(t *testing.T, keyType string, publicKey string) string {
	t.Helper()

	encoded, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"type":                   keyType,
			"latest_version":         1,
			"min_decryption_version": 1,
			"keys": map[string]any{
				"1": map[string]string{
					"public_key": publicKey,
				},
			},
		},
	})
	require.NoError(t, err)

	return string(encoded)
}

func sealingTransitKey(t *testing.T, keyType string) string {
	t.Helper()

	encoded, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"type":                   keyType,
			"latest_version":         1,
			"min_decryption_version": 1,
			"keys": map[string]any{
				"1": 1757937600,
			},
		},
	})
	require.NoError(t, err)

	return string(encoded)
}

func ed25519TransitKey(t *testing.T) string {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return transitKey(t, "ed25519", base64.StdEncoding.EncodeToString(publicKey))
}

func rsaTransitKey(t *testing.T, keyType string, bits int) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)

	der, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	require.NoError(t, err)

	return transitKey(t, keyType, string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})))
}

func signerFor(t *testing.T, config openbao.Config, algorithm string) crypto.Signer {
	t.Helper()

	manager, err := signr.New(signr.Config{
		Backend: config,
	})
	require.NoError(t, err)

	key, err := manager.GetGroup("signing").GetKey(algorithm)
	require.NoError(t, err)

	signer, err := key.Signer()
	require.NoError(t, err)

	return signer
}

func TestCreateRefusesAConfigWithoutAddress(t *testing.T) {
	// arrange
	config := openbao.Config{
		Mount: "transit",
		Token: openbao.StaticToken("token"),
	}

	// act
	_, err := config.Create()

	// assert
	assert.ErrorContains(t, err, "address")
}

func TestCreateRefusesAConfigWithoutMount(t *testing.T) {
	// arrange
	config := openbao.Config{
		Address: "http://127.0.0.1:8200",
		Token:   openbao.StaticToken("token"),
	}

	// act
	_, err := config.Create()

	// assert
	assert.ErrorContains(t, err, "mount")
}

func TestCreateRefusesAConfigWithoutTokenSourceInsteadOfPanicking(t *testing.T) {
	// arrange
	config := openbao.Config{
		Address: "http://127.0.0.1:8200",
		Mount:   "transit",
	}

	// act
	_, err := config.Create()

	// assert
	assert.ErrorContains(t, err, "token")
}

func TestCreateRefusesATokenSourceThatIsANilPointerInsteadOfPanicking(t *testing.T) {
	// arrange
	config := openbao.Config{
		Address: "http://127.0.0.1:8200",
		Mount:   "transit",
		Token:   (*openbao.StaticToken)(nil),
	}

	// act
	_, err := config.Create()

	// assert
	assert.ErrorContains(t, err, "token")
}

func TestAGroupNameThatWouldLeaveTheKeyPathIsRefused(t *testing.T) {
	// arrange
	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		reached = true
	}))
	t.Cleanup(server.Close)

	manager, err := signr.New(signr.Config{
		Backend: openbao.Config{
			Address: server.URL,
			Mount:   "transit",
			Token:   openbao.StaticToken("token"),
		},
	})
	require.NoError(t, err)

	// act
	_, err = manager.GetGroup("../../sys/mounts").GetKey("EdDSA")

	// assert
	assert.ErrorContains(t, err, "../../sys/mounts")
	assert.False(t, reached)
}

func TestARedirectNeverCarriesTheTokenElsewhere(t *testing.T) {
	// arrange
	leaked := ""
	elsewhere := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("X-Vault-Token")
	}))
	t.Cleanup(elsewhere.Close)

	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)

	manager, err := signr.New(signr.Config{
		Backend: openbao.Config{
			Address: redirecting.URL,
			Mount:   "transit",
			Token:   openbao.StaticToken("token"),
		},
	})
	require.NoError(t, err)

	// act
	_, err = manager.GetGroup("signing").GetKey("EdDSA")

	// assert
	assert.Error(t, err)
	assert.Empty(t, leaked)
}

func TestAKeyTransitHoldsAsAnotherTypeFailsClosed(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       rsaTransitKey(t, "rsa-2048", 2048),
	})

	manager, err := signr.New(signr.Config{
		Backend: config,
	})
	require.NoError(t, err)

	// act
	_, err = manager.GetGroup("signing").GetKey("RS256")

	// assert
	assert.ErrorContains(t, err, "rsa-2048")
}

func TestASealingKeyTransitHoldsAsAnotherTypeFailsClosed(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       sealingTransitKey(t, "aes128-gcm96"),
	})

	manager, err := signr.New(signr.Config{
		Backend: config,
	})
	require.NoError(t, err)

	// act
	_, err = manager.GetGroup("sealing").GetSealingKey("A256GCM")

	// assert
	assert.ErrorContains(t, err, "aes128-gcm96")
}

// a stream as signr writes it, with the wrapped key text given and the plaintext sealed under the data key
func streamWith(t *testing.T, wrapped string, dataKey []byte, plaintext []byte) []byte {
	t.Helper()

	stream := []byte{1, 0, byte(len(wrapped))}
	stream = append(stream, wrapped...)
	block, err := aes.NewCipher(dataKey)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	lastChunkNonce := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	return gcm.Seal(stream, lastChunkNonce, plaintext, []byte{1})
}

func TestAWrappedKeySpelledAnotherWayNeverReachesTransit(t *testing.T) {
	canonical := "vault:v1:QQ=="
	dataKey := bytes.Repeat([]byte{7}, 32)

	for _, respelled := range []string{
		"vault:v1:QR==",
		"vault:v1:QQ==\n",
		"vault:v1:Q\nQ==",
		"vault:v1:\r\nQQ==",
		"vault:v0:QQ==",
		"vault:v01:QQ==",
		"vault:v+1:QQ==",
	} {
		t.Run(respelled, func(t *testing.T) {
			// arrange
			sent := ""
			config := fakeTransit(t, transitAnswers{
				keyStatus: http.StatusOK,
				key:       sealingTransitKey(t, "aes256-gcm96"),
				plaintext: base64.StdEncoding.EncodeToString(dataKey),
				onDecrypt: func(ciphertext string) {
					sent = ciphertext
				},
			})

			manager, err := signr.New(signr.Config{
				Backend: config,
			})
			require.NoError(t, err)
			key, err := manager.GetGroup("sealing").GetSealingKey("A256GCM")
			require.NoError(t, err)
			opened, err := backendtest.Open(key, streamWith(t, canonical, dataKey, []byte("hello")), nil)
			require.NoError(t, err)
			require.Equal(t, []byte("hello"), opened)
			require.Equal(t, canonical, sent)
			sent = ""

			// act
			_, err = backendtest.Open(key, streamWith(t, respelled, dataKey, []byte("hello")), nil)

			// assert
			assert.Error(t, err)
			assert.Empty(t, sent)
		})
	}
}

func TestAMissingMountIsAnErrorInsteadOfAnEmptyGroup(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusNotFound,
		key:       `{"errors":["no handler for route \"transit/keys/signing-EdDSA\". route entry not found."]}`,
	})

	manager, err := signr.New(signr.Config{
		Backend: config,
	})
	require.NoError(t, err)

	// act
	_, err = manager.GetGroup("signing").PublicKeys()

	// assert
	assert.ErrorContains(t, err, "no handler for route")
}

func TestASignatureFromAnotherKeyVersionFailsClosed(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       ed25519TransitKey(t),
		signature: "vault:v2:" + base64.StdEncoding.EncodeToString([]byte("signature")),
	})
	signer := signerFor(t, config, "EdDSA")

	// act
	_, err := signer.Sign(rand.Reader, []byte("hello"), crypto.Hash(0))

	// assert
	assert.ErrorContains(t, err, "version")
}

func TestAnRSASignerRefusesMissingOptionsInsteadOfPanicking(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       rsaTransitKey(t, "rsa-4096", 4096),
		signature: "vault:v1:" + base64.StdEncoding.EncodeToString([]byte("signature")),
	})
	signer := signerFor(t, config, "RS256")
	digest := sha256.Sum256([]byte("hello"))

	// act
	_, err := signer.Sign(rand.Reader, digest[:], nil)

	// assert
	assert.Error(t, err)
}

func TestAnEdDSASignerRefusesAHashInsteadOfSigningTheDigestAsAMessage(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       ed25519TransitKey(t),
		signature: "vault:v1:" + base64.StdEncoding.EncodeToString([]byte("signature")),
	})
	signer := signerFor(t, config, "EdDSA")
	digest := sha256.Sum256([]byte("hello"))

	// act
	_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)

	// assert
	assert.ErrorContains(t, err, "ed25519")
}

func TestAnRSASignerRefusesPSSInsteadOfAnsweringPKCS1v15(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       rsaTransitKey(t, "rsa-4096", 4096),
		signature: "vault:v1:" + base64.StdEncoding.EncodeToString([]byte("signature")),
	})
	signer := signerFor(t, config, "RS256")
	digest := sha256.Sum256([]byte("hello"))

	// act
	_, err := signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{
		Hash: crypto.SHA256,
	})

	// assert
	assert.ErrorContains(t, err, "pss")
}

func TestAnRSASignerRefusesAHashTransitDoesNotSign(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       rsaTransitKey(t, "rsa-4096", 4096),
		signature: "vault:v1:" + base64.StdEncoding.EncodeToString([]byte("signature")),
	})
	signer := signerFor(t, config, "RS256")
	digest := make([]byte, 28)

	// act
	_, err := signer.Sign(rand.Reader, digest, crypto.SHA224)

	// assert
	assert.ErrorContains(t, err, "SHA-224")
}

func TestAnRSASignerRefusesADigestOfTheWrongLength(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       rsaTransitKey(t, "rsa-4096", 4096),
		signature: "vault:v1:" + base64.StdEncoding.EncodeToString([]byte("signature")),
	})
	signer := signerFor(t, config, "RS256")

	// act
	_, err := signer.Sign(rand.Reader, []byte("hello"), crypto.SHA256)

	// assert
	assert.ErrorContains(t, err, "digest")
}

func TestAnRSAKeySmallerThanItsTypeFailsClosed(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       rsaTransitKey(t, "rsa-4096", 2048),
	})

	manager, err := signr.New(signr.Config{
		Backend: config,
	})
	require.NoError(t, err)

	// act
	_, err = manager.GetGroup("signing").GetKey("RS256")

	// assert
	assert.ErrorContains(t, err, "2048")
}

func TestA404WithoutAnErrorsListIsAnErrorInsteadOfAMissingKey(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusNotFound,
		key:       `{"message":"not found"}`,
	})

	manager, err := signr.New(signr.Config{
		Backend: config,
	})
	require.NoError(t, err)

	// act
	_, err = manager.GetGroup("signing").PublicKeys()

	// assert
	assert.ErrorContains(t, err, "404")
}

func TestAnEdDSASignatureByAnotherKeyFailsClosed(t *testing.T) {
	// arrange
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       ed25519TransitKey(t),
		signature: "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(otherKey, []byte("hello"))),
	})
	signer := signerFor(t, config, "EdDSA")

	// act
	_, err = signer.Sign(rand.Reader, []byte("hello"), crypto.Hash(0))

	// assert
	assert.ErrorContains(t, err, "does not verify")
}

func TestAnRSASignatureTheKeyDoesNotVerifyFailsClosed(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       rsaTransitKey(t, "rsa-4096", 4096),
		signature: "vault:v1:" + base64.StdEncoding.EncodeToString([]byte("x")),
	})
	signer := signerFor(t, config, "RS256")
	digest := sha256.Sum256([]byte("hello"))

	// act
	_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)

	// assert
	assert.ErrorContains(t, err, "does not verify")
}

func TestAnEdDSASignerRefusesAContextInsteadOfDroppingIt(t *testing.T) {
	// arrange
	config := fakeTransit(t, transitAnswers{
		keyStatus: http.StatusOK,
		key:       ed25519TransitKey(t),
		signature: "vault:v1:" + base64.StdEncoding.EncodeToString([]byte("signature")),
	})
	signer := signerFor(t, config, "EdDSA")

	// act
	_, err := signer.Sign(rand.Reader, []byte("hello"), &ed25519.Options{
		Context: "mungbean",
	})

	// assert
	assert.ErrorContains(t, err, "context")
}
