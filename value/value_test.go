package value_test

import (
	b "bytes"
	h "encoding/hex"
	"fmt"
	"math/big"
	"testing"

	v "github.com/nsheremet/esrp/value"
)

var hex = "034bf53e4f"
var bin = fmt.Sprintf("%q", "\x03K\xf5>O")
var bytes, _ = h.DecodeString(hex)
var num = big.NewInt(14159265359)

func TestValueCreatingToHex(t *testing.T) {
	value := v.New(hex)

	if value.Hex() != hex {
		t.Error("hex should be equal")
	}

	if value.Bin() != bin {
		t.Error("binary should be equql")
	}

	if !b.Equal(value.Bytes(), bytes) {
		t.Error("bytes should be equal")
	}
}

func TestValueCreatingToBytes(t *testing.T) {
	value := v.New(bytes)

	if value.Hex() != hex {
		t.Error("hex should be equal")
	}

	if value.Bin() != bin {
		t.Error("binary should be equql")
	}

	if !b.Equal(value.Bytes(), bytes) {
		t.Error("bytes should be equal")
	}
}

func TestValueCreatingToInt(t *testing.T) {
	value := v.New(num)

	if value.Hex() != hex {
		t.Error("hex should be equal")
	}

	if value.Bin() != bin {
		t.Error("binary should be equql")
	}

	if !b.Equal(value.Bytes(), bytes) {
		t.Error("bytes should be equal")
	}
}
