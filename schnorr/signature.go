// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2024 The Decred developers
// Copyright (c) 2024 Dogecoin Foundation
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// This code is originally from:
// https://github.com/decred/dcrd/blob/master/dcrec/secp256k1/schnorr/signature.go

package schnorr

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	// SignatureSize is the size of an encoded Schnorr signature.
	SignatureSize = 64
)

// Signature is a type representing a Schnorr signature.
type Signature struct {
	r secp256k1.FieldVal
	s secp256k1.ModNScalar
}

// NewSignature instantiates a new signature given some r and s values.
func NewSignature(r *secp256k1.FieldVal, s *secp256k1.ModNScalar) *Signature {
	var sig Signature
	sig.r.Set(r).Normalize() // CT
	sig.s.Set(s)             // CT
	return &sig
}

// R returns the r value of the signature.
func (sig *Signature) R() secp256k1.FieldVal {
	return sig.r
}

// S returns the s value of the signature.
func (sig *Signature) S() secp256k1.ModNScalar {
	return sig.s
}

// Serialize returns the Schnorr signature in the more strict format.
//
// The signatures are encoded as:
//
//	sig[0:32]  x coordinate of the point R, encoded as a big-endian uint256
//	sig[32:64] s, encoded also as big-endian uint256
func (sig Signature) Serialize() []byte {
	// Total length of returned signature is the length of r and s.
	var b [SignatureSize]byte
	sig.r.PutBytesUnchecked(b[0:32])  // CT
	sig.s.PutBytesUnchecked(b[32:64]) // CT
	return b[:]
}

// IsEqual compares this Signature instance to the one passed, returning true
// if both Signatures are equivalent. A signature is equivalent to another, if
// they both have the same scalar value for R and S.
func (sig Signature) IsEqual(otherSig *Signature) bool {
	return sig.r.Equals(&otherSig.r) && sig.s.Equals(&otherSig.s) // CT except &&
}

// ParseSignature parses a signature according to the EC-Schnorr-Dogecoin
// specification in constant time and enforces the following additional
// restrictions specific to secp256k1:
//
// - The r component must be in the valid range for secp256k1 field elements
// - The s component must be in the valid range for secp256k1 scalars
func ParseSignature(sig []byte) (*Signature, error) {
	// The signature must be the correct length.
	sigLen := len(sig)
	if sigLen != SignatureSize {
		return nil, ErrSigSize
	}

	// The signature is validly encoded at this point, however, enforce
	// additional restrictions to ensure r is in the range [0, p-1], and s is in
	// the range [0, n-1] since valid Schnorr signatures are required to be in
	// that range per spec.
	var r secp256k1.FieldVal
	if overflow := r.SetBytes((*[32]byte)(sig[0:32])); overflow != 0 { // CT
		return nil, ErrSigInvalidR
	}
	var s secp256k1.ModNScalar
	if overflow := s.SetBytes((*[32]byte)(sig[32:64])); overflow != 0 { // CT
		return nil, ErrSigInvalidS
	}

	// Return the signature.
	return NewSignature(&r, &s), nil // CT
}
