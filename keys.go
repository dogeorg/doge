package doge

import (
	"crypto/rand"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type KeyType = int // keyECPriv,keyECPub,keyBip32Priv,keyBip32Pub,dogeMainNet,dogeTestNet
const (
	keyNone      KeyType = 0
	keyECPriv    KeyType = 1
	keyECPub     KeyType = 2
	keyBip32Priv KeyType = 3
	keyBip32Pub  KeyType = 4
)

const (
	ECPrivKeyLen            = 32 // bytes.
	ECPubKeyCompressedLen   = 33 // bytes: [x02/x03][32-X] 2=even 3=odd
	ECPubKeyUncompressedLen = 65 // bytes: [x04][32-X][32-Y]
)

type ECPrivKey = *[32]byte            // 32 bytes.
type ECPubKeyCompressed = *[33]byte   // 33 bytes with 0x02 or 0x03 prefix.
type ECPubKeyUncompressed = *[65]byte // 65 bytes with 0x04 prefix.

func GenerateECPrivKey() (ECPrivKey, error) {
	// GeneratePrivateKeyFromRand ensures the returned key satisfies ECKeyIsValid.
	// This can return an error if entropy is not available.
	pk, err := secp256k1.GeneratePrivateKeyFromRand(rand.Reader)
	if err != nil {
		return nil, err
	}
	ret := (*[32]byte)(pk.Serialize()) // returns 32 bytes; Go 1.17 cast to underlying array
	pk.Zero()                          // clear key material.
	return ret, nil
}

func ECPubKeyFromECPrivKey(pk ECPrivKey) ECPubKeyCompressed {
	var privKey secp256k1.PrivateKey
	overflow := privKey.Key.SetBytes(pk)
	if (overflow | privKey.Key.IsZeroBit()) != 0 {
		panic("ECPubKeyFromECPrivKey: invalid private key")
	}
	K := privKey.PubKey()
	privKey.Zero() // clear key material.
	if !K.IsOnCurve() {
		panic("ECPubKeyFromECPrivKey: public key is not on the curve!")
	}
	pub := (*[33]byte)(K.SerializeCompressed()) // returns 33 bytes
	return pub
}

func ECKeyIsValid(pk ECPrivKey) bool {
	// If overflow != 0, it means the ECPrivKey is >= N (the order
	// of the secp256k1 curve) which is not a valid private key.
	var modN secp256k1.ModNScalar
	overflow := modN.SetBytes(pk)
	// "Further, 0 is not a valid private key. It is up to the caller
	// to provide a value in the appropriate range of [1, N-1]."
	overflow |= modN.IsZeroBit()
	modN.Zero() // clear key material.
	return overflow == 0
}
