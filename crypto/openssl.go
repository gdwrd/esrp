package crypto

import (
	"github.com/spacemonkeygo/openssl"
)

// OpenSSL struct crypto engine
//
// Provides:
// - hash: SHA1, SHA256, SHA384, SHA512
// - kdf: pbkdf2 with selected hash, legacy implementation H(salt | password)
// - mac: hmac with selected hash, legacy H(message | key)
type OpenSSL struct {
	hasher openssl.EVP_MD
}

// DefaultOptions {map[string]interface{}}
// Defaults to SHA256_PBKDF2_HMAC
var DefaultOptions = map[string]interface{}{
	"hash": openssl.EVP_SHA256,
}

// NewOpenSSL public function:
//
// Params:
// - hash {openssl.EVP_MD} Hash Type
//
// Response:
// - {OpenSSL}
func NewOpenSSL(hash openssl.EVP_MD) OpenSSL {
	return OpenSSL{
		hasher: hash,
	}
}
