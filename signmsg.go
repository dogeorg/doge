package doge

import (
	"errors"

	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/dogeorg/doge/schnorr"
)

type ECPubKeySchnorr = *[32]byte  // 32 byte X-coordinate-only public key, encoded as a big-endian uint256
type SchnorrSignature = *[64]byte // 64 byte signature, encoding (R.x, s) as big-endian uint256

var schnorrSign = schnorr.New()

var ErrInvalidPrivateKey = errors.New("invalid private key")

// SignMessage signs an arbitrary message with a private key.
// Returns an error if the private key is invalid.
func SignMessage(privKey ECPrivKey, msg []byte) (SchnorrSignature, error) {
	hash := blake256.Sum256(msg)
	var priv secp256k1.PrivateKey
	if priv.Key.SetBytes(privKey) != 0 {
		return nil, ErrInvalidPrivateKey
	}
	defer priv.Zero()
	sig, err := schnorrSign.Sign(&priv, hash[:])
	if err != nil {
		return nil, err
	}
	sigBytes := (*[64]byte)(sig.Serialize())
	return sigBytes, nil
}

// VerifyMessage verifies an arbitrary message with a public key
// and signature; the signature and public key are also validated,
// i.e. all parameters can be untrusted data.
func VerifyMessage(pubKey ECPubKeySchnorr, msg []byte, sig SchnorrSignature) bool {
	hash := blake256.Sum256(msg)
	vsig, err := schnorr.ParseSignature(sig[:])
	if err != nil {
		return false
	}
	return schnorrSign.Verify(vsig, hash[:], pubKey[:])
}
