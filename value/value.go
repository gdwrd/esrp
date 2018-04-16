package value

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
)

// Value Struct
// Allows representation-independent operation on SRP values
//
// While most of the crypto works with binary representation,
// all the transfers between client and server usually utilize
// hex strings and math operations uses integers.
//
type Value struct {
	bytes []byte
	hex   string
	int   *big.Int
}

// New function: {Value} Constructor
//
// Params:
// - arg {interface} hex string
//
// Response:
// - value {Value} value with hex attribute
func New(arg interface{}) (value Value) {
	if v, ok := arg.(string); ok {
		value.hex = v
	} else if v, ok := arg.([]byte); ok {
		value.hex = fmt.Sprintf("%x", string(v))
	} else if v, ok := arg.(*big.Int); ok {
		value.hex = fmt.Sprintf("%x", string(v.Bytes()))
	}

	buff, err := hex.DecodeString(value.hex)

	if err != nil {
		log.Fatal(err)
	}

	value.bytes = buff
	value.int = new(big.Int).SetBytes([]byte(value.bytes))

	return value
}

// Bytes function
//
// Represent value as byte array
//
// Response:
// - d {[]byte} byte array
func (v Value) Bytes() []byte {
	return v.bytes
}

// Hex function
//
// Represent value as hex
//
// Response:
// - hex {String} hex in UTF-8
func (v Value) Hex() string {
	return v.hex
}

// Int function
//
// Represent value as big.Int
//
// Response:
// - {big.Int}
func (v Value) Int() *big.Int {
	return v.int
}

// Bin function
//
// Returns binary string that use the \xNN notation
// https://blog.golang.org/strings
//
// Response:
// - {string}
func (v Value) Bin() string {
	return fmt.Sprintf("%q", v.bytes)
}
