// Package secret encrypts what must not sit in the database in the clear
// (API tokens, the tunnel's token): AES-256-GCM with one key per
// installation, kept apart from the database.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyFile is the name of the key in the data directory.
const KeyFile = "secret.key"

// Box encrypts and decrypts with one key.
type Box struct{ aead cipher.AEAD }

// Load returns the box of an installation. The key is envKey when it is set
// (32 bytes in base64, `openssl rand -base64 32`), otherwise the file
// secret.key in dir, which is created on first use. Keep the key out of
// backups of the database, or a stolen backup opens the secrets.
func Load(dir, envKey string) (*Box, error) {
	if env := strings.TrimSpace(envKey); env != "" {
		k, err := base64.StdEncoding.DecodeString(env)
		if err != nil || len(k) != 32 {
			return nil, errors.New("the secret key must be 32 bytes in base64 (openssl rand -base64 32)")
		}
		return New(k)
	}
	path := filepath.Join(dir, KeyFile)
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("%s is damaged: it must hold 32 bytes in base64", path)
		}
		return New(k)
	case errors.Is(err, os.ErrNotExist):
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		// O_EXCL: two processes starting at once must not each write a key.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			return Load(dir, "")
		}
		if err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
		_, werr := f.WriteString(base64.StdEncoding.EncodeToString(k) + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return nil, fmt.Errorf("write %s: %w", path, werr)
		}
		return New(k)
	default:
		return nil, err
	}
}

// New returns a box for a 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("secret: the key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plain for object, the name it is stored under: a sealed
// value copied to another name does not open there.
func (b *Box) Seal(object string, plain []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plain, []byte(object)), nil
}

// Open decrypts what Seal returned for the same object.
func (b *Box) Open(object string, sealed []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("secret: value too short")
	}
	plain, err := b.aead.Open(nil, sealed[:n], sealed[n:], []byte(object))
	if err != nil {
		return nil, errors.New("secret: cannot decrypt (was the secret key changed?)")
	}
	return plain, nil
}
