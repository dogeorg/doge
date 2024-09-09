package doge

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	SerializedBip32KeyLength = 4 + 1 + 4 + 4 + 32 + 33
	HardenedKey              = 0x80000000
)

var ErrCannotDerive = errors.New("cannot derive private key from public key")
var ErrBadSeed = errors.New("bad seed: must be 16-64 bytes")
var ErrAnotherSeed = errors.New("cannot derive a valid master key from this seed (generate another seed)")
var ErrNextIndex = errors.New("cannot derive a valid child key at this key index (try the next index)")
var ErrHardened = errors.New("cannot derive a public key from a hardened parent key")
var ErrTooDeep = errors.New("key derivation path is too long (more than 255)")

// https://en.bitcoin.it/wiki/BIP_0032
type Bip32Key struct {
	keyType            KeyType      // pub_priv_key holds the private key (otherwise public key)
	depth              byte         // 0x00 for master nodes, 0x01 for level-1 derived keys, ...
	child_number       uint32       // child number. ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
	chain              *ChainParams // chain params derived from Bip32 'version' field
	parent_pub         *[33]byte    // parent public key (used to generate ParentFingerprint on demand)
	parent_fingerprint uint32       // the fingerprint of the parent's key (0x00000000 if master key)
	chain_code         [32]byte     // the chain code
	pub_priv_key       [33]byte     // public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
}

// IsPrivate is true if the Bip32Key holds a Private key
// (otherwise it holds the corresponding Public key)
func (key *Bip32Key) IsPrivate() bool {
	return key.keyType == keyBip32Priv
}

// ChainParams returns the chain this key belongs to.
func (key *Bip32Key) ChainParams() *ChainParams {
	return key.chain
}

// EncodeWIF encodes this key in Bip32 WIF format (dgpv,dgub)
func (key *Bip32Key) EncodeWIF() string {
	return EncodeBip32WIF(key)
}

// Public returns the Public Bip32Key corresponding to a Private Bip32Key.
// If key is already a Public Bip32Key, the same *Bip32Key is returned.
func (key *Bip32Key) Public() *Bip32Key {
	if key.keyType == keyBip32Priv {
		// https://en.bitcoin.it/wiki/BIP_0032#Private_parent_key_%E2%86%92_public_child_key
		// The returned chain code c is just the passed chain code.
		pub := Bip32Key{
			keyType:            keyBip32Pub,
			depth:              key.depth,              // sideways: same depth
			child_number:       key.child_number,       // sideways: same index
			chain:              key.chain,              // same chain
			chain_code:         key.chain_code,         // sideways: same chain code
			parent_pub:         key.parent_pub,         // same parent pubkey (or nil)
			parent_fingerprint: key.parent_fingerprint, // same parent fingerprint (or nil)
		}
		// N((k, c)) → (K, c) computes the extended public key corresponding to an extended private key
		// (the "neutered" version, as it removes the ability to sign transactions).
		// The returned key K is point(k).
		serPK := ECPubKeyFromECPrivKey((*[32]byte)(key.pub_priv_key[1:33])) // serP(point(k))
		copy(pub.pub_priv_key[0:33], serPK[0:33])
		return &pub
	} else {
		return key
	}
}

// ParentFingerprint is the fingerprint for the parent's public key.
// This is the fingerprint stored in the Bip32 Serialization Format (EncodeBip32WIF)
func (key *Bip32Key) ParentFingerprint() uint32 {
	// We defer the calculation of the key fingerprint until it's either
	// requested by software or the key is serialized in EncodeBip32WIF.
	if key.parent_pub == nil {
		// Already have the parent's fingerprint, either because this is
		// the master key, or this key came from DecodeBip32WIF, or because
		// we already calculated it.
		return key.parent_fingerprint
	} else {
		// "Extended keys can be identified by the Hash160 of the
		//  serialized ECDSA public key K, ignoring the chain code."
		hash := Hash160(key.parent_pub[:])
		key.parent_fingerprint = binary.BigEndian.Uint32(hash[0:4])
		key.parent_pub = nil // only calculate once
		return key.parent_fingerprint
	}
}

// ThisKeyFingerprint is the fingerprint for this key's public key.
// NOTE: this is not the ParentFingerprint() sored in Bip23 WIF format!
// This is primarily included for tests.
func (key *Bip32Key) ThisKeyFingerprint() uint32 {
	var pubkey ECPubKeyCompressed
	if key.keyType == keyBip32Priv {
		pk := (*[32]byte)(key.pub_priv_key[1:33]) // Go 1.17 cast to underlying array
		pubkey = ECPubKeyFromECPrivKey(pk)        // serP(point(k))
	} else {
		pubkey = &key.pub_priv_key
	}
	hash := Hash160(pubkey[:])
	return binary.BigEndian.Uint32(hash[0:4])
}

// GetECPrivKey gets a copy of the underlying private key.
func (key *Bip32Key) GetECPrivKey() (ECPrivKey, error) {
	if key.keyType == keyBip32Priv {
		pk := [ECPrivKeyLen]byte{}
		pk = *(*[32]byte)(key.pub_priv_key[1:33]) // copy
		return &pk, nil
	} else {
		return nil, fmt.Errorf("Bip32Key is not a private key")
	}
}

// GetECPrivKey gets a copy of the underlying public key.
func (key *Bip32Key) GetECPubKey() ECPubKeyCompressed {
	if key.keyType == keyBip32Priv {
		// contains a private key.
		return ECPubKeyFromECPrivKey((*[32]byte)(key.pub_priv_key[1:33])) // Go 1.17 cast to underlying array
	} else {
		// contains a public key.
		pub := [ECPubKeyCompressedLen]byte{}
		pub = key.pub_priv_key // copy
		return &pub
	}
}

func (key *Bip32Key) Clear() {
	*key = Bip32Key{}
}

// DeriveChild derives a child key according to BIP-32.
// Path is a list of child key indexes.
// If an index is >= HardenedKey, the derived key will be hardened.
// For a Private Bip32Key we use PrivateCKD on each path element;
// for a Public key we use PublicCKD.
func (key *Bip32Key) DeriveChild(path []uint32) (*Bip32Key, error) {
	if key.keyType == keyBip32Priv {
		return key.PrivateCKD(path)
	} else {
		parent := key
		clear_parent := false
		for _, index := range path {
			child, err := parent.PublicCKD(index)
			if clear_parent {
				// don't leave derived intermediates in memory
				parent.Clear()
			}
			if err != nil {
				return &Bip32Key{}, err
			}
			parent = child
			clear_parent = true
		}
		return parent, nil
	}
}

func (key *Bip32Key) PrivateCKD(path []uint32) (*Bip32Key, error) {
	if len(path) > 255 || int(key.depth)+len(path) > 255 {
		// key too deep (encoded as a single byte in WIF)
		return &Bip32Key{}, ErrTooDeep
	}
	if key.keyType == keyBip32Priv {
		// Private parent key → private child key
		if len(path) > 0 {
			return key.ckd_private_derivation(path)
		} else {
			return key, nil
		}
	} else {
		// Public parent key → This is not possible.
		return &Bip32Key{}, ErrCannotDerive
	}
}

// assumes: key is a private key; 0 < len(path) <= 255
func (key *Bip32Key) ckd_private_derivation(path []uint32) (*Bip32Key, error) {
	var Ibuf [64]byte
	var chaincode_buf [32]byte
	var privkey_buf [33]byte
	var s32 [4]byte
	var parseILModN, kparModN secp256k1.ModNScalar
	var err error
	last := len(path) - 1
	child := Bip32Key{
		keyType:      keyBip32Priv,
		depth:        key.depth + byte(len(path)),
		child_number: path[last],
		chain:        key.chain,
	}
	// copy in the parent's private key and chaincode.
	// trade-off: simplifies buffer zeroing and reduces code complexity.
	copy(privkey_buf[:], key.pub_priv_key[:])
	copy(chaincode_buf[:], key.chain_code[:])
	for it, index := range path {
		hash := hmac.New(sha512.New, chaincode_buf[:])
		var parent_pub *[33]byte
		if index&HardenedKey != 0 {
			// Private derivation.
			// "let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i))
			// (Note: The 0x00 pads the private key to make it 33 bytes long)"
			hash.Write(privkey_buf[:]) // 0x00 || ser256(k)
		} else {
			// Public derivation.
			// "let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i))"
			// Note: save the parent pubkey in case this is the last iteration.
			parent_pub = ECPubKeyFromECPrivKey((*[32]byte)(privkey_buf[1:33])) // serP(K = point(k))
			hash.Write(parent_pub[:])                                          // serP(point(kpar))
		}
		ser32(s32[:], index)
		hash.Write(s32[:])
		I := hash.Sum(Ibuf[:0])
		hash.Reset() // clear hash state (far too expensive!)
		// "Split I into two 32-byte sequences, IL and IR.
		// The returned child key ki is parse256(IL) + kpar (mod n)."
		// Note: (*[32]byte) aliases the underlying array (Go 1.17)
		overflow := parseILModN.SetBytes((*[32]byte)(I[0:32])) // overflow if >= N
		// "In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid,
		// and one should proceed with the next value for i.
		// (Note: this has probability lower than 1 in 2^127)"
		if overflow != 0 {
			// In case parse256(IL) ≥ n … the resulting key is invalid"
			err = ErrNextIndex
			break // clear all sensitive state and return err
		}
		kparModN.SetBytes((*[32]byte)(privkey_buf[1:33])) // kpar (parent private key)
		parseILModN.Add(&kparModN)                        // parse256(IL) + kpar (mod n)
		if parseILModN.IsZero() {
			// "In case … ki = 0, the resulting key is invalid"
			err = ErrNextIndex
			break // clear all sensitive state and return err
		}
		if it < last {
			parseILModN.PutBytesUnchecked(privkey_buf[1:33])
			copy(chaincode_buf[:], I[32:64])
			if !ECKeyIsValid((*[32]byte)(privkey_buf[1:33])) {
				// should be unreachable (already checked overflow and ki=0)
				panic("PrivateCKD: generated invalid private key")
			}
		} else {
			// final iteration: copy the private key and chaincode into
			// the child Bip32Key to return.
			parseILModN.PutBytesUnchecked(child.pub_priv_key[1:33])
			copy(child.chain_code[:], I[32:64])
			if !ECKeyIsValid((*[32]byte)(child.pub_priv_key[1:33])) {
				// should be unreachable (already checked overflow and ki=0)
				panic("PrivateCKD: generated invalid private key")
			}
			// generate the parent's pubkey to include in the child Bip32Key
			// so we can derive the parent fingerprint later.
			if parent_pub != nil {
				child.parent_pub = parent_pub // from "Public derivation" above
			} else {
				// note: privkey_buf still contains the parent private key.
				child.parent_pub = ECPubKeyFromECPrivKey((*[32]byte)(privkey_buf[1:33])) // serP(K = point(k))
			}
			break
		}
	}
	parseILModN.Zero()        // clear to avoid leaking key material
	kparModN.Zero()           // clear to avoid leaking chaincode material
	memZero(Ibuf[:])          // clear to avoid leaking hash material
	memZero(chaincode_buf[:]) // clear to avoid leaking chaincode material
	memZero(privkey_buf[:])   // clear to avoid leaking key material
	return &child, err
}

func (key *Bip32Key) PublicCKD(index uint32) (*Bip32Key, error) {
	if key.depth == 255 {
		// depth is encoded as a single byte in WIF
		return &Bip32Key{}, ErrTooDeep
	}
	if key.keyType == keyBip32Priv {
		// Private parent key → public child key
		// "N(CKDpriv((kpar, cpar), i)) (works always)."
		child, err := key.PrivateCKD([]uint32{index}) // XXX temp hack
		if err != nil {
			return &Bip32Key{}, err
		}
		return child.Public(), nil
	} else {
		// Public parent key → public child key
		// "CKDpub((Kpar, cpar), i) → (Ki, ci) computes a child extended public key from the parent extended public key.
		// It is only defined for non-hardened child keys."
		// Check whether i ≥ 2^31 (whether the child is a hardened key).
		if index >= HardenedKey {
			return &Bip32Key{}, ErrHardened
		}
		// "I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i))."
		var data [1 + 32 + 4]byte
		copy(data[0:33], key.pub_priv_key[0:33]) // serP(Kpar)
		ser32(data[33:37], index)                // ser32(i))
		I := hmacSha512(key.chain_code[:], data[:])
		memZero(data[:])
		// "Split I into two 32-byte sequences, IL and IR.
		// The returned child key Ki is point(parse256(IL)) + Kpar."
		var parseIL secp256k1.ModNScalar
		overflow := parseIL.SetBytes((*[32]byte)(I[0:32])) // overflow if >= N
		// "In case parse256(IL) ≥ n or Ki is the point at infinity, the resulting key is invalid,
		// and one should proceed with the next value for i."
		if (overflow | parseIL.IsZeroBit()) != 0 {
			memZero(I)
			return &Bip32Key{}, ErrNextIndex
		}
		var pointIL, Kpar, pointILplusKpar secp256k1.JacobianPoint
		secp256k1.ScalarBaseMultNonConst(&parseIL, &pointIL) // pointIL = point(parse256(IL))
		KparAffine, err := secp256k1.ParsePubKey(key.pub_priv_key[:])
		if err != nil {
			// Unlikely: means we previously derived in invalid public key.
			memZero(I)
			return &Bip32Key{}, err
		}
		KparAffine.AsJacobian(&Kpar)                             // Kpar in point form
		secp256k1.AddNonConst(&pointIL, &Kpar, &pointILplusKpar) // point(parse256(IL)) + Kpar
		pointILplusKpar.ToAffine()
		Ki := secp256k1.NewPublicKey(&pointILplusKpar.X, &pointILplusKpar.Y)
		if !Ki.IsOnCurve() {
			// Unlikely: means the sum of two points on the curve is not a point on the curve.
			memZero(I)
			return &Bip32Key{}, ErrNextIndex
		}
		// Return Bip32Key for the child.
		var parent_pub [33]byte = key.pub_priv_key // copy
		child := Bip32Key{
			keyType:      keyBip32Pub,
			depth:        key.depth + 1,
			child_number: index,
			chain:        key.chain,
			parent_pub:   &parent_pub,
		}
		childPubKey := Ki.SerializeCompressed() // 33 bytes
		copy(child.pub_priv_key[0:33], childPubKey[0:33])
		// "The returned chain code ci is IR."
		copy(child.chain_code[:], I[32:64])
		memZero(I)
		return &child, nil
	}
}

// Bip32MasterFromSeed derives the Bip32 master key from an entropy seed.
// Note: bip39.SeedFromMnemonic generates an appropriate seed (also GenerateRandomMnemonic)
func Bip32MasterFromSeed(seed []byte, chain *ChainParams) (*Bip32Key, error) {
	// https://en.bitcoin.it/wiki/BIP_0032#Master_key_generation
	// Generate a seed byte sequence S of a chosen length (between 128 and 512 bits; 256 bits is advised) from a (P)RNG.
	if len(seed) < 16 || len(seed) > 64 {
		return &Bip32Key{}, ErrBadSeed
	}
	if chain == nil {
		panic("Bip32MasterFromSeed chain parameter is required")
	}
	// Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
	I := hmacSha512([]byte("Bitcoin seed"), seed)
	// Split I into two 32-byte sequences, IL and IR
	// Use parse256(IL) as master secret key, and IR as master chain code.
	masterKey := I[0:32]
	chainCode := I[32:64]
	// In case parse256(IL) is 0 or parse256(IL) ≥ n, the master key is invalid.
	if !ECKeyIsValid((*[32]byte)(masterKey)) {
		memZero(I)
		return &Bip32Key{}, ErrAnotherSeed
	}
	key := Bip32Key{
		keyType:            keyBip32Priv,
		depth:              0, // "0x00 for master nodes"
		child_number:       0, // "0x00000000 if master key"
		chain:              chain,
		parent_fingerprint: 0, // "0x00000000 if master key"
	}
	copy(key.chain_code[:], chainCode)
	copy(key.pub_priv_key[1:], masterKey)
	memZero(I)
	return &key, nil
}

// DecodeBip32WIF decodes a WIF-encoded Bip32Key (dgpv,dgub)
// chain is optional, will auto-detect if nil.
func DecodeBip32WIF(extendedKey string, chain *ChainParams) (*Bip32Key, error) {
	data, err := Base58DecodeCheck(extendedKey)
	if err != nil {
		return nil, err
	}
	if len(data) != SerializedBip32KeyLength {
		memZero(data) // clear for security.
		return nil, fmt.Errorf("DecodeBip32WIF: not a bip32 extended key (wrong length)")
	}
	var key Bip32Key
	version := deser32(data[0:])
	if chain == nil {
		ok := false
		if ok, chain = ChainFromBip32Version(version, true); !ok {
			memZero(data) // clear for security.
			return nil, fmt.Errorf("DecodeBip32WIF: not a bip32 extended key (unknown chain prefix)")
		}
	}
	if version == chain.Bip32_PrivKey_Prefix {
		key.keyType = keyBip32Priv
	} else if version == chain.Bip32_PubKey_Prefix {
		key.keyType = keyBip32Pub
	} else {
		memZero(data) // clear for security.
		return nil, fmt.Errorf("DecodeBip32WIF: not a bip32 extended key (wrong prefix)")
	}
	key.depth = data[4]
	key.parent_fingerprint = deser32(data[5:])
	key.child_number = deser32(data[9:])
	key.chain = chain
	if copy(key.chain_code[:], data[13:45]) != 32 {
		memZero(data) // clear for security.
		key.Clear()
		panic("DecodeBip32WIF: wrong chain_code length")
	}
	if copy(key.pub_priv_key[:], data[45:78]) != 33 {
		memZero(data) // clear for security.
		key.Clear()
		panic("DecodeBip32WIF: wrong key length")
	}
	memZero(data) // clear key for security.
	key_pre := key.pub_priv_key[0]
	if !(key_pre == 0x00 && key.keyType == keyBip32Priv) && !((key_pre == 0x02 || key_pre == 0x03) && key.keyType == keyBip32Pub) {
		key.Clear()
		return nil, fmt.Errorf("DecodeBip32WIF: invalid key prefix byte")
	}
	return &key, nil
}

// EncodeBip32WIF encodes a Bip32Key in WIF format (dgpv,dgub)
func EncodeBip32WIF(key *Bip32Key) string {
	data := [SerializedBip32KeyLength]byte{}
	var version uint32
	if key.keyType == keyBip32Priv {
		version = key.chain.Bip32_PrivKey_Prefix
	} else if key.keyType == keyBip32Pub {
		version = key.chain.Bip32_PubKey_Prefix
	} else {
		panic("EncodeBip32WIF: invalid keyType")
	}
	ser32(data[0:4], version)
	data[4] = key.depth
	ser32(data[5:9], key.ParentFingerprint())
	ser32(data[9:13], key.child_number)
	if copy(data[13:45], key.chain_code[:]) != 32 {
		panic("EncodeBip32WIF: wrong chain_code length")
	}
	if copy(data[45:78], key.pub_priv_key[:]) != 33 {
		panic("EncodeBip32WIF: wrong key length")
	}
	wif := Base58EncodeCheck(data[:])
	memZero(data[:])
	return wif
}

// HMAC-SHA512 returns 64 bytes.
func hmacSha512(key []byte, data []byte) []byte {
	hash := hmac.New(sha512.New, key)
	hash.Write(data[:]) // Hash interface: "It never returns an error."
	buf := make([]byte, 0, 64)
	buf = hash.Sum(buf)
	hash.Reset() // clear hash state
	return buf
}

func ser32(to []byte, i uint32) {
	// serialize a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first.
	to[0] = byte(i >> 24)
	to[1] = byte(i >> 16)
	to[2] = byte(i >> 8)
	to[3] = byte(i >> 0)
}

func deser32(from []byte) uint32 {
	// deserialize a 32-bit unsigned integer, most significant byte first.
	return (uint32(from[0]) << 24) | (uint32(from[1]) << 16) | (uint32(from[2]) << 8) | (uint32(from[3]))
}
