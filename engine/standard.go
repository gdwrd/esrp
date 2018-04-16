package engine

import (
	"math/big"

	v "github.com/nsheremet/esrp/value"
)

// Standard is Default engine
//
// This engine doesn't involve username, uses "K" as a master secret
// # and doesn't perform XOR computation in "M".
// # Also, it tries to conform RFC5054 as much as possible.
type Standard struct {
	Engine
}

// CalcX function: Calculate private key (x)
//
// 	 x = KDF(s, p)
//
// Params:
// - password {string}   plain-text password in UTF8 string
// - salt     {v.Value}  random generated salt (s)
// - username {string}   plain-text username in UTF8 string (not used here)
//
// Returns: {v.Value} private key (x)
func (e Standard) CalcX(password, salt string) v.Value {
	return e.crypto.PasswordHash(v.New(salt), password)
}

// CalcM function: Calculate validation message (M) (M1 in some specs)
//
// 	 M = HMAC(K, A | s | B)
//
// Params:
// - kk {v.Value} private session key (K)
// - aa {v.Value} client ephemeral value (A)
// - bb {v.Value} server ephemeral value (B)
// - ss {v.Value} premaster secret (S) (not used here)
// - salt     {v.Value} random generated salt (s)
// - username {string} plain-text username in UTF8 string (not used here)
//
// Returns: {v.Value} validation message (M)
func (e Standard) CalcM(kk, aa, bb, ss, salt v.Value, username string) v.Value {
	val := big.NewInt(0)
	val = val.Add(aa.Int(), salt.Int())
	val = val.Add(val, bb.Int())

	return e.crypto.KeyedHash(kk, v.New(val))
}

// CalcM2 function: Calculate optional response validation message (HAMK) (M2 in some specs)
//
//	 M2 = HMAC(K, A | M)
//
// Params:
// - kk {v.Value} private session key (K)
// - aa {v.Value} client ephemeral value (A)
// - mm {v.Value} validation message (M)
// - ss {v.Value} premaster secret (S) (not used here)
//
// Returns: {v.Value}
func (e Standard) CalcM2(kk, aa, mm, _ss v.Value) v.Value {
	val := big.NewInt(0)
	val = val.Add(aa.Int(), mm.Int())

	return e.crypto.KeyedHash(kk, v.New(val))
}
