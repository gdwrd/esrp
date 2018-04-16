package crypto

import (
	"bytes"
	"crypto"
	"math/big"
	"math/rand"
	"testing"

	// s "github.com/nsheremet/esrp/crypto"
	"github.com/nsheremet/esrp/value"
)

var val = value.New("07c0")

func TestStandardHWithSHA1(t *testing.T) {
	instance := NewStandard(crypto.SHA1)
	subj := instance.H(val)

	if subj.Hex() != "00ff3b16b0f555d3feb62f988fb3aab81c1c50ea" {
		t.Error("hash should be equal")
	}
}

func TestStandardHWithSHA256(t *testing.T) {
	instance := NewStandard(crypto.SHA256)
	subj := instance.H(val)

	if subj.Hex() != "34b902c818ebdb547c4aa8d161dd701bd5f78ac3df6b5ab7fac3c35dae795e56" {
		t.Error("hash should be equal")
	}
}

func TestStandardHWithSHA384(t *testing.T) {
	instance := NewStandard(crypto.SHA384)
	subj := instance.H(val)

	if subj.Hex() != "87f7dd5d5e3b905a1f8317a170516d95717b488c1d8d49e5254cf30bbf5bbd822adcbf60c1b9aa0c100c28e2505fdfe8" {
		t.Error("hash should be equal")
	}
}

func TestStandardHWithSHA512(t *testing.T) {
	instance := NewStandard(crypto.SHA512)
	subj := instance.H(val)

	if subj.Hex() != "ff860fd40517a0de51b3747587177f02aeffc629dd37934035ec79113733041a42c23ba503cf9294284bb5fc77d4242e17664fb4d1c69ee4e27e96d4c17a3fcd" {
		t.Error("hash should be equal")
	}
}

var salt = value.New(big.NewInt(1117))
var password = "verysecure"

func TestStandardPasswordHashWithSHA1(t *testing.T) {
	instance := NewStandard(crypto.SHA1)
	subj := instance.PasswordHash(salt, password)

	if subj.Hex() != "f2960ac838b31a4dcb1b4ddf5bf6af4ecec4eb38" {
		t.Error("should be equel")
	}
}

func TestStandardPasswordHashWithSHA256(t *testing.T) {
	instance := NewStandard(crypto.SHA256)
	subj := instance.PasswordHash(salt, password)

	if subj.Hex() != "9e4cae19d40bc58571ae7237cb13563f5598da5d596389cb55e8311be2d90cbe" {
		t.Error("should be equal")
	}
}

func TestStandardPasswordHashWithSHA384(t *testing.T) {
	instance := NewStandard(crypto.SHA384)
	subj := instance.PasswordHash(salt, password)

	if subj.Hex() != "6f4618cc20ea1c25aa5e475099c609d4b5955fe859bc0198fa333cddf096108d50cf8361f374f20ac0362a16026f51a0" {
		t.Error("should be equal")
	}
}

func TestStandardPasswordHashWithSHA512(t *testing.T) {
	instance := NewStandard(crypto.SHA512)
	subj := instance.PasswordHash(salt, password)

	if subj.Hex() != "868b4c9f961fdb2ee4d066d74de2c0432eafa01b714c2f749c4b13d1e370e04bb57eaecdb1f36fa15646439710f886a0fe974b59228178e1a61bbbd3aaae135b" {
		t.Error("Should be equal")
	}
}

var key = value.New("f4ffd830b255f778b9d88966e87ae1d72702227cfcbeae4bd1e4b39fff136060")
var msg = value.New("07c0")

func TestStandardPasswordHashLegacyWithSHA1(t *testing.T) {
	instance := NewStandardWithParams(crypto.SHA1, true, false)
	subj := instance.PasswordHash(salt, password)

	if subj.Hex() != "4fb8f49a9526730f9b49ae5915011fd43c0dd598" {
		t.Error("should be equal")
	}
}

func TestStandardPasswordHashLegacyWithSHA256(t *testing.T) {
	instance := NewStandardWithParams(crypto.SHA256, true, false)
	subj := instance.PasswordHash(salt, password)

	if subj.Hex() != "ee36a8a3b95a6d3e02680b603f71f71e911a6f69c384aa0d18bd03f18c810d1f" {
		t.Error("should be equal")
	}
}

func TestStandardPasswordHashLegacyWithSHA384(t *testing.T) {
	instance := NewStandardWithParams(crypto.SHA384, true, false)
	subj := instance.PasswordHash(salt, password)

	if subj.Hex() != "3b9b35652dd6c98a73b31cf9e020482a4d2400632601cc7e9cc095952b7434c7214a4b6657fe7ba4c1d6bca8e1cb6c9a" {
		t.Error("should be equal")
	}
}

func TestStandardPasswordHashLegacyWithSHA512(t *testing.T) {
	instance := NewStandardWithParams(crypto.SHA512, true, false)
	subj := instance.PasswordHash(salt, password)

	if subj.Hex() != "d17cf68960f86086ca789d7e56e3fd050a8848ccbf5d7034ce449c8a897c6b6932c76e20a48e4cc4898e7fd436b93c6dcc8f852cb498f156e4aed9c096bfd279" {
		t.Error("should be equal")
	}
}

func TestStandardKeyedHashWithSHA1(t *testing.T) {
	instance := NewStandard(crypto.SHA1)
	subj := instance.KeyedHash(key, msg)

	if subj.Hex() != "d11bbc50282edef28dbd924a8d034621ae18bba0" {
		t.Error("should be equal")
	}
}

func TestStandardKeyedHashWithSHA256(t *testing.T) {
	instance := NewStandard(crypto.SHA256)
	subj := instance.KeyedHash(key, msg)

	if subj.Hex() != "ecfa17f317164259824287aa9feabeda9c784e7d672b118965ebff33f5373abe" {
		t.Error("should be equal")
	}
}

func TestStandardKeyedHashWithSHA384(t *testing.T) {
	instance := NewStandard(crypto.SHA384)
	subj := instance.KeyedHash(key, msg)

	if subj.Hex() != "99d890c210a33198ea612fbe8d469950f8bb16f1dbd4b68e79d6306d0eff142fb237be16abb09c22b08a5bdf76a56607" {
		t.Error("should be equal")
	}
}

func TestStandardKeyedHashWithSHA512(t *testing.T) {
	instance := NewStandard(crypto.SHA512)
	subj := instance.KeyedHash(key, msg)

	if subj.Hex() != "8a93a38e2f274f99cdd25be0620bcee180e1cec062b22b09c314b051edf51ab3fb221b191e569d500bce1708f0e6ed7b745a1df6575c05c7ed5742a78ca7ad71" {
		t.Error("should be equal")
	}
}

func TestStandardKeyedHashLegacySHA1(t *testing.T) {
	instance := NewStandardWithParams(crypto.SHA1, false, true)
	subj := instance.KeyedHash(key, msg)

	if subj.Hex() != "370422c37f40c245bcc614c733ad39c7b796bed6" {
		t.Error("should be equal")
	}
}

func TestStandardKeyedHashLegacySHA256(t *testing.T) {
	instance := NewStandardWithParams(crypto.SHA256, false, true)
	subj := instance.KeyedHash(key, msg)

	if subj.Hex() != "72cd133608ddfae3ebeb26b757c0b825bb4195c2153be5a7a543ed7212c18949" {
		t.Error("should be equal")
	}
}

func TestStandardKeyedHashLegacySHA384(t *testing.T) {
	instance := NewStandardWithParams(crypto.SHA384, false, true)
	subj := instance.KeyedHash(key, msg)

	if subj.Hex() != "8fb3c4a42f47946c0fb686670810462a8b87aa3eb49d491c73380bdeddd1799a94a2d8fd0114efea3f6de5edd00f91eb" {
		t.Error("should be equel")
	}
}

func TestStandardSecureCompareTrue(t *testing.T) {
	instance := Standard{}
	a := value.New("00ff3b16b0f555d3feb62f988fb3aab81c1c50ea")
	b := value.New("00ff3b16b0f555d3feb62f988fb3aab81c1c50ea")

	if !instance.SecureCompare(a, b) {
		t.Error("values should be equel")
	}
}

func TestStandardSecureCompareFalse(t *testing.T) {
	instance := Standard{}
	a := value.New("00ff3b16b0f555d3feb62f988fb3aab81c1c50ea")
	b := value.New("00ff3b16b0f555d3feb62f988fb3aab81c1c50eb")

	if instance.SecureCompare(a, b) {
		t.Error("values should be equal")
	}
}

func TestStandardRandom(t *testing.T) {
	instance := Standard{}
	length := rand.Intn(32)
	subj := instance.Random(length)

	if len(subj.Bytes()) != length {
		t.Error("length should be equal")
	}
}

func TestStandardPadding(t *testing.T) {
	val := []byte{0, 2}
	expected := []byte{0, 0, 0, 2}

	if !bytes.Equal(expected, pad(val, 4)) {
		t.Error("pad should make")
	}
}
