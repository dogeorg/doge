// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2024 The Decred developers
// Copyright (c) 2024 Dogecoin Foundation
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// This code is originally from:
// https://github.com/decred/dcrd/blob/master/dcrec/secp256k1/schnorr/signature.go

package schnorr

import (
	"errors"

	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	// scalarSize is the size of an encoded big endian scalar.
	scalarSize = 32

	// PubKeySize is the size of an encoded Schnorr public key.
	PubKeySize = 32
)

var (
	// rfc6979ExtraDataDogecoin is the extra data to feed to RFC6979 when generating
	// the deterministic nonce for the EC-Schnorr-Dogecoin scheme.  This ensures
	// the same nonce is not generated for the same message and key as for other
	// signing algorithms such as ECDSA.
	//
	// It is equal to BLAKE-256([]byte("EC-Schnorr-Dogecoin"))
	rfc6979ExtraDataDogecoin = [32]byte{
		0xc1, 0x3f, 0x0e, 0xfc, 0x5e, 0xc0, 0xe8, 0x4d,
		0x8d, 0x7c, 0xcf, 0xbc, 0x78, 0x9a, 0xe2, 0x33,
		0x12, 0x2b, 0xdb, 0x3c, 0x7b, 0xf0, 0xfa, 0x06,
		0x2f, 0xb2, 0xaa, 0x7f, 0xe9, 0x0a, 0x6f, 0x98,
	}
	// Tagged hash inspired by BIP 340: this tag is equal to
	// blake256.Sum256([]byte("Dogecoin/challenge"))
	// The tag is included twice as a prefix to the BLAKE-256
	// hash input, as specified in BIP 340.
	challengeTagDogecoin = [32]byte{
		0xe4, 0xb2, 0x45, 0x1d, 0x37, 0x06, 0xcb, 0x8b,
		0x7d, 0xf0, 0x30, 0x5f, 0xf3, 0x5f, 0x2d, 0xa4,
		0x9a, 0xfe, 0xde, 0xc3, 0xd8, 0x08, 0x0b, 0x4d,
		0x5d, 0x6e, 0xd4, 0x92, 0xe6, 0xe3, 0x8e, 0xff,
	}
)

var ErrSigSize = errors.New("invalid signature: wrong length")
var ErrSigInvalidR = errors.New("invalid signature: r >= field prime")
var ErrSigInvalidS = errors.New("invalid signature: s >= curve order")
var ErrInvalidHashLen = errors.New("invalid message hash length (want 32 bytes)")
var ErrInvalidPubKey = errors.New("invalid public key")
var ErrPubKeyNotOnCurve = errors.New("pubkey point is not on curve")
var ErrSigRAtInifnity = errors.New("calculated R point is the point at infinity")
var ErrSigRYIsOdd = errors.New("calculated R y-value is odd")
var ErrUnequalRValues = errors.New("calculated R point was not given R")
var ErrPrivateKeyIsZero = errors.New("invalid private key (is zero)")
var ErrSchnorrNonceValue = errors.New("generated nonce is zero")
var ErrSchnorrHashValue = errors.New("hash of (r || P || m) >= curve order")

type SchnorrImpl struct {
	ChallengeHasher  *blake256.Hasher256
	RFC6979ExtraData []byte
	PubKeyInHash     bool
}

// New creates a Schnorr Signature implementation with Dogecoin
// tagged-hashing and RFC6979ExtraData.
// This allows tests to use different parameters.
func New() SchnorrImpl {
	return SchnorrImpl{
		ChallengeHasher:  newTaggedBLAKE(&challengeTagDogecoin),
		RFC6979ExtraData: rfc6979ExtraDataDogecoin[:],
		PubKeyInHash:     true,
	}
}

func newTaggedBLAKE(tag *[32]byte) *blake256.Hasher256 {
	hasher := blake256.NewHasher256()
	hasher.WriteBytes(tag[:]) // twice per BIP 340
	hasher.WriteBytes(tag[:])
	return hasher
}

// lift_x returns the Public Key Point with even Y, given X.
// This implements the function lift_x() from BIP 340.
func lift_x(pubKeyBytes []byte) (*secp256k1.PublicKey, error) {
	if len(pubKeyBytes) != PubKeySize {
		return nil, ErrInvalidPubKey
	}
	var pubKeyX, pubKeyY secp256k1.FieldVal
	overflow := pubKeyX.SetBytes((*[32]byte)(pubKeyBytes)) // CT
	if overflow != 0 {
		return nil, ErrInvalidPubKey // x >= p
	}
	if !secp256k1.DecompressY(&pubKeyX, false, &pubKeyY) { // CT except leaks odd/even
		return nil, ErrPubKeyNotOnCurve // no such point exists
	}
	pubKeyY.Normalize()                                    // CT
	return secp256k1.NewPublicKey(&pubKeyX, &pubKeyY), nil // CT
}

// schnorrVerify attempts to verify the signature for the provided hash and
// public key and either returns nil if successful or a specific error
// indicating why it failed if not successful.
//
// This differs from the exported Verify method in that it returns a specific
// error to support better testing while the exported method simply returns a
// bool indicating success or failure.
func (sgn SchnorrImpl) schnorrVerify(sig *Signature, hash []byte, pubKeyBytes []byte) error {
	// The algorithm for producing a EC-Schnorr-Dogecoin signature is described in
	// README.md and is reproduced here for reference:
	//
	//
	// 1. Fail if m is not 32 bytes
	// 2. Fail if Q is not a point on the curve
	// 3. Fail if r >= p
	// 4. Fail if s >= n
	// 5. e = taggedBLAKE-256(r || q || m) (Ensure r is padded to 32 bytes)
	// 6. Fail if e >= n
	// 7. R = s*G + e*Q
	// 8. Fail if R is the point at infinity
	// 9. Fail if R.y is odd
	// 10. Verified if R.x == r

	// Step 1.
	//
	// Fail if m is not 32 bytes
	if len(hash) != scalarSize {
		return ErrInvalidHashLen
	}

	// Step 2.
	//
	// Fail if Q is not a point on the curve.
	// This recovers an even Y coordinate from the provided x coordinate.
	pubKey, err := lift_x(pubKeyBytes) // CT except leaks odd/even
	if err != nil {
		return err
	}
	if !pubKey.IsOnCurve() { // CT
		return ErrPubKeyNotOnCurve
	}

	// Step 3.
	//
	// Fail if r >= p
	//
	// Note this is already handled by the fact r is a field element.

	// Step 4.
	//
	// Fail if s >= n
	//
	// Note this is already handled by the fact s is a mod n scalar.

	// Step 5.
	//
	// e = taggedBLAKE-256(r || q || m) (Ensure r is padded to 32 bytes)
	var r_bytes [scalarSize]byte
	sig.r.PutBytesUnchecked(r_bytes[:]) // CT
	taggedBLAKE := *sgn.ChallengeHasher // copy the tagged hasher
	taggedBLAKE.WriteBytes(r_bytes[:])  // r
	if sgn.PubKeyInHash {
		taggedBLAKE.WriteBytes(pubKeyBytes) // q
	}
	taggedBLAKE.WriteBytes(hash)       // m
	commitment := taggedBLAKE.Sum256() // CT

	// Step 6.
	//
	// Fail if e >= n
	var e secp256k1.ModNScalar
	if overflow := e.SetBytes(&commitment); overflow != 0 { // CT
		return ErrSchnorrHashValue
	}

	// Step 7.
	//
	// R = s*G + e*Q
	var Q, R, sG, eQ secp256k1.JacobianPoint
	pubKey.AsJacobian(&Q)                         // CT
	secp256k1.ScalarBaseMultNonConst(&sig.s, &sG) // non-CT
	secp256k1.ScalarMultNonConst(&e, &Q, &eQ)     // non-CT
	secp256k1.AddNonConst(&sG, &eQ, &R)           // non-CT

	// Step 8.
	//
	// Fail if R is the point at infinity
	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() { // data-dependent branches
		return ErrSigRAtInifnity
	}

	// Step 9.
	//
	// Fail if R.y is odd
	//
	// Note that R must be in affine coordinates for this check.
	R.ToAffine()     // CT
	if R.Y.IsOdd() { // CT
		return ErrSigRYIsOdd
	}

	// Step 10.
	//
	// Verified if R.x == r
	//
	// Note that R must be in affine coordinates for this check.
	if !sig.r.Equals(&R.X) { // CT
		return ErrUnequalRValues
	}

	return nil
}

// Verify returns whether or not the signature is valid for the provided hash
// and public key. The public key is always 32 bytes, encoding an X coordinate
// only, which corresponds (always) to an even Y coordinate.
func (sgn SchnorrImpl) Verify(sig *Signature, hash []byte, pubKey []byte) bool {
	return sgn.schnorrVerify(sig, hash, pubKey) == nil
}

// zeroArray zeroes the memory of a scalar array.
func zeroArray(a *[scalarSize]byte) {
	for i := 0; i < scalarSize; i++ {
		a[i] = 0x00
	}
}

// schnorrSign generates an EC-Schnorr-Dogecoin signature over the secp256k1 curve
// for the provided hash (which should be the result of hashing a larger
// message) using the given nonce and private key.  The produced signature is
// deterministic (same message, nonce, and key yield the same signature) and
// canonical.
//
// WARNING: The hash MUST be 32 bytes and both the nonce and private keys must
// NOT be 0.  Since this is an internal use function, these preconditions MUST
// be satisified by the caller.
func (sgn SchnorrImpl) schnorrSign(privKey, nonce *secp256k1.ModNScalar, hash []byte, pubKeyBytes []byte) (*Signature, error) {
	// The algorithm for producing a EC-Schnorr-Dogecoin signature is described in
	// README.md and is reproduced here for reference:
	//
	// G = curve generator
	// n = curve order
	// d = private key
	// m = message
	// r, s = signature
	//
	// 1. Fail if m is not 32 bytes
	// 2. Fail if d = 0 or d >= n
	// 2a. Negate d if dG.y is odd (Public Key has odd Y coordinate)
	// 3. Use RFC6979 to generate a deterministic nonce k in [1, n-1]
	//    parameterized by the private key, message being signed, extra data
	//    that identifies the scheme, and an iteration count
	// 4. R = kG
	// 5. Negate nonce k if R.y is odd (R.y is the y coordinate of the point R)
	// 6. r = R.x (R.x is the x coordinate of the point R)
	// 7. e = taggedBLAKE-256(r || q || m) (Ensure r is padded to 32 bytes)
	// 8. Repeat from step 3 (with iteration + 1) if e >= n
	// 9. s = k - e*d mod n
	// 10. Return (r, s)

	// NOTE: Steps 1-3 are performed by the caller.
	//
	// Step 4.
	//
	// R = kG
	var R secp256k1.JacobianPoint
	k := *nonce
	secp256k1.ScalarBaseMultNonConst(&k, &R) // non-CT (nonce)

	// Step 5.
	//
	// Negate nonce k if R.y is odd (R.y is the y coordinate of the point R)
	//
	// Note that R must be in affine coordinates for this check.
	R.ToAffine()     // CT
	if R.Y.IsOdd() { // data-dependent: non-CT (nonce)
		k.Negate() // CT
	}

	// Step 6.
	//
	// r = R.x (R.x is the x coordinate of the point R)
	r := &R.X

	// Step 7.
	//
	// e = taggedBLAKE-256(r || q || m) (Ensure r is padded to 32 bytes)
	var r_bytes [scalarSize]byte
	r.PutBytesUnchecked(r_bytes[:])     // CT
	taggedBLAKE := *sgn.ChallengeHasher // copy the tagged hasher
	taggedBLAKE.WriteBytes(r_bytes[:])  // r
	if sgn.PubKeyInHash {
		taggedBLAKE.WriteBytes(pubKeyBytes) // q
	}
	taggedBLAKE.WriteBytes(hash)       // m
	commitment := taggedBLAKE.Sum256() // CT

	// Step 8.
	//
	// Repeat from step 1 (with iteration + 1) if e >= N
	var e secp256k1.ModNScalar
	if overflow := e.SetBytes(&commitment); overflow != 0 { // CT
		k.Zero()                        // CT
		return nil, ErrSchnorrHashValue // e >= N
	}

	// Step 9.
	//
	// s = k - e*d mod n
	s := new(secp256k1.ModNScalar).Mul2(&e, privKey).Negate().Add(&k) // CT
	k.Zero()                                                          // CT

	// Step 10.
	//
	// Return (r, s)
	return NewSignature(r, s), nil // CT
}

// Sign generates an EC-Schnorr-Dogecoin signature over the secp256k1 curve for the
// provided hash (which should be the result of hashing a larger message) using
// the given private key.  The produced signature is deterministic (same message
// and same key yield the same signature) and canonical.
//
// Note that the current signing implementation has a few remaining variable
// time aspects which make use of the private key and the generated nonce, which
// can expose the signer to constant time attacks.  As a result, this function
// should not be used in situations where there is the possibility of someone
// having EM field/cache/etc access.
func (sgn SchnorrImpl) Sign(privKey *secp256k1.PrivateKey, hash []byte) (*Signature, error) {
	// The algorithm for producing a EC-Schnorr-Dogecoin signature is described in
	// README.md and is reproduced here for reference:
	//
	// G = curve generator
	// n = curve order
	// d = private key
	// m = message
	// r, s = signature
	//
	// 1. Fail if m is not 32 bytes
	// 2. Fail if d = 0 or d >= n
	// 2a. Negate d if dG.y is odd (Public Key has odd Y coordinate)
	// 3. Use RFC6979 to generate a deterministic nonce k in [1, n-1]
	//    parameterized by the private key, message being signed, extra data
	//    that identifies the scheme, and an iteration count
	// 4. R = kG
	// 5. Negate nonce k if R.y is odd (R.y is the y coordinate of the point R)
	// 6. r = R.x (R.x is the x coordinate of the point R)
	// 7. e = taggedBLAKE-256(r || q || m) (Ensure r is padded to 32 bytes)
	// 8. Repeat from step 3 (with iteration + 1) if e >= n
	// 9. s = k - e*d mod n
	// 10. Return (r, s)

	// Step 1.
	//
	// Fail if m is not 32 bytes
	if len(hash) != scalarSize {
		return nil, ErrInvalidHashLen
	}

	// Step 2.
	//
	// Fail if d = 0 or d >= n
	privKeyScalar := &privKey.Key
	if privKeyScalar.IsZero() { // CT
		return nil, ErrPrivateKeyIsZero
	}

	// Step 2a (BIP-340 Steps 4 & 5)
	// P = d*G
	// Negate d if P.y is odd.
	// This affects the evenness of the result of Signing step 9
	// (s = k - e*d mod n) ensuring s*G has the same Y-evenness as e*Q
	// (public keys always have even-Y in our scheme, as well as in BIP 340)
	// Do this before generating the nonce to avoid malleability of the
	// otherwise deterministic nonce.
	pub := privKey.PubKey()
	pubBytes := pub.SerializeCompressed()
	if pubBytes[0] == secp256k1.PubKeyFormatCompressedOdd {
		privKeyScalar.Negate()
	}

	var privKeyBytes [scalarSize]byte
	privKeyScalar.PutBytes(&privKeyBytes) // CT
	defer zeroArray(&privKeyBytes)        // CT
	for iteration := uint32(0); ; iteration++ {
		// Step 3.
		//
		// Use RFC6979 to generate a deterministic nonce k in [1, n-1]
		// parameterized by the private key, message being signed, extra data
		// that identifies the scheme, and an iteration count
		k := secp256k1.NonceRFC6979(privKeyBytes[:], hash, sgn.RFC6979ExtraData[:], // CT
			nil, iteration)

		// Steps 4-10.
		sig, err := sgn.schnorrSign(privKeyScalar, k, hash, pubBytes[1:]) // non-CT (nonce)
		k.Zero()                                                          // CT
		if err != nil {
			// Try again with a new nonce.
			continue
		}

		return sig, nil
	}
}
