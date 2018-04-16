// Package engine for SRP calculation engine
package engine

import (
	"math/big"

	c "github.com/nsheremet/esrp/crypto"
	g "github.com/nsheremet/esrp/group"
	v "github.com/nsheremet/esrp/value"
)

// Engine is a struct and EngineInterface is an interface for crypto engine
//
// This class defines the foundation for SRP values computations
// Different implementations may be constructed, basing on this class
// There are 4 vectors for customizing as seen on different implementations:
//
// 1. x and M computation (see #calc_x and #calc_M)
// 2. Crypto primitives (see ERSP::Crypto)
// 3. Type conversion (see ESRP::Crypto#H and ESRP::Value)
// 4. Padding (see #pad)
//
// So, to provide compatibility, we can use different engines and customize
// esrp.Crypto.
// For example:
//   Subclass of ESRP::Engine defines
//   CalcX as PasswordHash(s, p) ignoring the 'I' argument
//   CalcM as KeyedHash(S, A | B) ignoring 'K', 'I' and 's' args
//   CalcM2 as H(A | M | K) ignoring 'S' argument
//   Pad do nothing (returns value as is)
//   Substruct of esrp.Crypto provides
//   H as SHA1 with hex string concatenation
//   PasswordHash as SHA1(salt | password)
//   KeyedHash as SHA1(value | key)
// In this way, we can build Server or Client compatible with almost every existing
// implementation. But if it's not necessary, the default engines are recommended.
//
// One more thing to mention: design docs says "All arithmetic is done modulo N",
// but it's not clear what does it mean. After reviewing actual implementations,
// the most popular interpretation is:
//
// * "a^b" operation treats as "a^b mod N"
// * "B" have an additional "mod N" in the end (see https://www.computest.nl/blog/exploiting-two-buggy-srp-implementations/)
//
// Other interpretations are not supported, but could be monkey-patched (mostly
// additional "(u * x mod N)" in client S).
//
// Glossary (as seen on http://srp.stanford.edu/design.html):
//   N    A large safe prime (N = 2q+1, where q is prime)
//   g    A generator modulo N
//   k    Multiplier parameter k = H(N, g)
//   s    User's salt
//   I    Username
//   p    Cleartext Password
//   H()  One-way hash function
//   ^    (Modular) Exponentiation
//   u    Random scrambling parameter
//   a,b  Secret ephemeral values
//   A,B  Public ephemeral values
//   x    Private key (derived from p and s)
//   v    Password verifier
//
type Engine struct {

	// Current crypto engine
	//
	// Response: {esrp.Crypto}
	crypto c.Crypto
	N      v.Value
	G      v.Value
	k      v.Value
}

// Interface (engine.Interface) is an interface for crypto engine
type Interface interface {

	// Interface function: Calculate private key (x)
	//
	//This function is a keystone of verifier's (v) strengthness
	//
	// The SRP-6a design docs describes 'x' as:
	//
	//   x = H(s | p)
	//
	// However, different implementations and standards defines their own,
	// more complicated calculations:
	//
	//   x = H(s | H(I) | H(p))
	//   x = H(s | H(I | ":" | p)) - RFC2945, RFC5054
	//
	// All this calculations uses the same one-way hash function (SHA in general),
	// as for other computations, which is designed to be fast and not computationally
	// intensive. This can be improved by using more computational heavy algorithms.
	// Various password-based key derivation functions (such as bcrypt, scrypt, argon2)
	// can be a pretty good option. So, it can look like:
	//
	//   x = KDF(s, p)
	//
	// Also, the username (I) is frequently seen in calculation of 'x'. From one side,
	// it mitigates inpersonation attacks. From the other side, majority of the modern
	// webapps allows users to change their login or use different emails for auth. So
	// the username argument left optional. Various engine implementations may use or
	// skip it. IMPORTANT: server SHOULD implement some mechanism to limit unsuccessful
	// authentication attempts. Especially when using implementation without involving
	// username (I) in 'x'
	//
	// Finally, the preparation of username (I) and password (p) using the stringprep (RFC3454)
	// may apply. RFC5054 requires SASLprep profile (RFC4013) for stringprep.
	//
	// Papers
	// * http://srp.stanford.edu/ndss.html#itspub
	// * https://web.archive.org/web/20150403175113/http://www.leviathansecurity.com/wp-content/uploads/SpiderOak-Crypton_pentest-Final_report_u.pdf - page 12
	//
	// Params:
	// - password {string}      plain-text password in UTF8 string
	// - salt     {esrp.Value} random generated salt (s)
	// - username {string}      plain-text username in UTF8 string (optional)
	//
	// Response:
	// - {esrp.Value} private key (x)
	CalcX(password string, salt v.Value, username string) v.Value

	// Interface function: Calculate validation message (M) (M1 in some specs)
	//
	// Validation message is a proof of validity of private session key (K)
	// The SRP-6a design docs and RFC2945 describes ("One possible way is") 'M' as:
	//
	//   M = H(H(N) xor H(g) | H(I) | s | A | B | K)
	//
	// As with 'x' there are some differences between implementations:
	//
	//   M = H(A | B | S)
	//   M = H(A | B | K)
	//
	// The main sense for 'M' is to transmit 'K' without it's compromentation.
	// In first case, H(N) XOR H(g) adds additional computational heaviness and
	// a grain of salt, but they doesn't do too much, so all variants is pretty
	// good and the choice of formula depends on use case and is up to implementor.
	//
	// Also, the RFC2945 recommends usage of keyed hash transforms (like HMAC)
	// with 'K' as a key. Hardened implementation may look like:
	//
	//   M = HMAC(K, H(N) xor H(g) | H(I) | s | A | B)
	//
	// or
	//
	//   M = HMAC(K, A | s | B)
	//
	// or similar.
	//
	// Params:
	// - kk {esrp.Value} private session key (K)
	// - aa {esrp.Value} client ephemeral value (A)
	// - bb {esrp.Value} server ephemeral value (B)
	// - ss {esrp.Value} premaster secret (S)
	// - salt     {esrp.Value} random generated salt (s)
	// - username {string} plain-text username in UTF8 string (optional)
	//
	// Response:
	// - {esrp.Value} validation message (M)
	CalcM(kk, aa, bb, ss, salt v.Value, username string) v.Value

	// Interface function: Calculate optional response validation message (HAMK) (M2 in some specs)
	//
	//   M2 = H(A | M | K)
	//
	// Also seen as
	//
	//   M2 = H(A | M | S)
	//
	// Proves that the server has a valid verifier (v)
	//
	// As for M1, HMAC with 'K' as key may be used:
	//
	//   M2 = HMAC(K, A | M)
	//
	// Params:
	// - kk {esrp.Value} private session key (K)
	// - aa {esrp.Value} client ephemeral value (A)
	// - mm {esrp.Value} validation message (M)
	// - ss {esrp.Value} premaster secret (S)
	//
	// Response:
	// - {esrp.Value}
	CalcM2(kk, aa, mm, ss v.Value) v.Value
}

// New function Constructor
//
// Params:
// - crypto {esrp.Crypto} crypto engine
// - group  {esrp.Group} group params
func New(crypto c.Crypto, group g.Group) Engine {
	return Engine{
		crypto: crypto,
		N:      group.N,
		G:      group.G,
		k:      crypto.H(group.N, group.G),
	}
}

// K function: Multiplier parameter (k)
//
// k = H(N | g)
//   k = H(N | PAD(g)) - RFC5054
//
// Response:
// - {ESRP::Value} multiplier parameter (k)
func (e Engine) K() v.Value {
	if e.k.Hex() == "" {
		return e.crypto.H(e.N, e.G)
	}

	return e.k
}

// CalcV function: Calculate password verifier (v)
//
//   v = g^x
//
// Params:
// - x {esrp.Value} private key (x)
//
// Returns:
// - {esrp.Value} password verifier (v)
func (e Engine) CalcV(x v.Value) v.Value {
	return e.modExp(e.G, x)
}

// CalcA function: Calculate public client ephemeral value (A)
//
//   A = g^a
//
// The host MUST abort the authentication if A mod N == 0
//
// Params:
// - a {esrp.Value} secret client ephemeral value (a)
//
// Response:
// - {esrp.Value} public client ephemeral value (A)
func (e Engine) CalcA(a v.Value) v.Value {
	return e.modExp(e.G, a)
}

// CalcB function: Calculate public server ephemeral value (B)
//
//   B = kv + g^b % N
//
// The client MUST abort authentication if B % N == 0
//
// Note the additional mod N in the end: https://www.computest.nl/blog/exploiting-two-buggy-srp-implementations/
//
// Params:
// - b {esrp.Value} secret server ephemeral value (b)
//
// Response:
// - {esrp.Value} public server ephemeral value (B)
func (e Engine) CalcB(b, val v.Value) v.Value {
	mul := new(big.Int).Mul(e.k.Int(), val.Int())
	res := new(big.Int).Add(mul, e.modExp(e.G, b).Int())
	return v.New(new(big.Int).Mod(res, e.N.Int()))
}

// CalcU function: random scrambling parameter (u)
//
//   u = H(A | B)
//   u = H(PAD(A) | PAD(B))
//
// Params:
// - aa {esrp.Value} client ephemeral value (A)
// - bb {esrp.Value} server ephemeral value (B)
//
// Response:
// - {esrp.Value} random scrambling parameter (u)
func (e Engine) CalcU(aa, bb v.Value) v.Value {
	return e.crypto.H(aa, bb)
}

// CalcClientS function: Calcalate client session key (S)
//
//   S = (B - (k * g^x)) ^ (a + (u * x))
//
// Params:
// - bb {esrp.Value} public server ephemeral value (B)
// - a  {esrp.Value} secret client ephemeral value (a)
// - x  {esrp.Value} private key (x)
// - u  {esrp.Value} random scrambling parameter (u)
//
// Response:
// - {esrp.Value} client session key (S)
func (e Engine) CalcClientS(bb, a, x, u v.Value) v.Value {
	mul := new(big.Int).Mul(e.k.Int(), e.modExp(e.G, x).Int())
	left := new(big.Int).Sub(bb.Int(), mul)
	right := new(big.Int).Add(a.Int(), new(big.Int).Mul(u.Int(), x.Int()))

	return e.modExp(v.New(left), v.New(right))
}

// CalcServerS function: Calculate server session key (S)
//
//   S = (A * v^u) ^ b
//
// Params:
// - aa {esrp.Value} client ephemeral value (A)
// - b  {esrp.Value} secret server ephemeral value (b)
// - v  {esrp.Value} password verifier (v)
// - u  {esrp.Value} random scrambling parameter (u)
//
// Response:
// - {esrp.Value} server session key (S)
func (e Engine) CalcServerS(aa, b, val, u v.Value) v.Value {
	left := new(big.Int).Mul(aa.Int(), e.modExp(val, u).Int())
	return e.modExp(v.New(left), b)
}

// CalcK function: Calculate private session key (K)
//
//   K = H(S)
//
// This key calculates independently on both client and server and may be used
// as private key on later symmetric cryptography exchange between client and
// server.
//
// Params:
// - ss {ESPR::Value} premaster secret (S)
//
// Response:
// - {ESRP::Value} private session key (K)
func (e Engine) CalcK(ss v.Value) v.Value {
	return e.crypto.H(ss)
}

// modExp function: modular exponentation
//
// As mentioned above, this method reflects '^' operator in SRP
// which interprets as 'a^b%N' ('a EXP b MOD N')
//
// Params:
// - a {esrp.Value}
// - b {esrp.Value}
//
// Response:
// - {esrp.Value}
func (e Engine) modExp(a v.Value, b v.Value) v.Value {
	return v.New(new(big.Int).Exp(a.Int(), b.Int(), e.N.Int()))
}
