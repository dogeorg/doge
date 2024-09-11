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
func (key *Bip32Key) DeriveChild(path []uint32, useSLIP10 bool) (*Bip32Key, error) {
	if key.keyType == keyBip32Priv {
		return key.PrivateCKD(path, useSLIP10)
	} else {
		return key.PublicCKD(path, useSLIP10)
	}
}

func (key *Bip32Key) PrivateCKD(path []uint32, useSLIP10 bool) (*Bip32Key, error) {
	if len(path) > 255 || int(key.depth)+len(path) > 255 {
		// key too deep (encoded as a single byte in WIF)
		return &Bip32Key{}, ErrTooDeep
	}
	if key.keyType == keyBip32Priv {
		// Private parent key → private child key
		if len(path) == 0 {
			return key, nil
		}
		// temporary buffers: reused for every path element.
		var I_buf [64]byte
		var chaincode_buf [32]byte
		var privkey_buf [33]byte
		var idx32 [4]byte
		var ki, kpar secp256k1.ModNScalar
		var err error
		// prepare the output Bip32Key so we can copy into its fields during the last iteration.
		last := len(path) - 1
		child := Bip32Key{
			keyType:      keyBip32Priv,
			depth:        key.depth + byte(len(path)),
			child_number: path[last],
			chain:        key.chain,
		}
		// loop over nodes along the derivation path.
		in_privkey := &key.pub_priv_key
		in_chaincode := &key.chain_code
	pathloop:
		for it, index := range path {
			ser32(idx32[:], index)
			hash := hmac.New(sha512.New, in_chaincode[:])
			var parent_pub *[33]byte // saves parent pubkey on last iteration
			if index&HardenedKey != 0 {
				// Private derivation.
				// "let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i))
				// (Note: The 0x00 pads the private key to make it 33 bytes long)"
				hash.Write(in_privkey[:]) // 0x00 || ser256(k)
			} else {
				// Public derivation.
				// "let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i))"
				parent_pub = ECPubKeyFromECPrivKey((*[32]byte)(in_privkey[1:33])) // serP(K = point(k))
				hash.Write(parent_pub[:])                                         // serP(point(kpar))
			}
			var IR *[32]byte
			for {
				hash.Write(idx32[:])
				I := hash.Sum(I_buf[:0]) // I aliases I_buf
				hash.Reset()             // clear key material (far too expensive!)
				// "Split I into two 32-byte sequences, IL and IR."
				// Note: (*[32]byte) aliases the underlying array (Go 1.17)
				IL := (*[32]byte)(I[0:32])
				IR = (*[32]byte)(I[32:64])
				// "The returned child key ki is parse256(IL) + kpar (mod n)."
				overflow := ki.SetBytes(IL) // overflow if >= N
				// "In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid,
				// and one should proceed with the next value for i.
				if overflow != 0 {
					// parse256(IL) ≥ n (probability < 2^-127)
					if useSLIP10 {
						// SLIP-0010: "let I = HMAC-SHA512(Key = cpar, Data = 0x01 || IR || ser32(i) and restart at step 2."
						hash.Write([]byte{0x01}) // NB. hash was reset above
						hash.Write(IR[:])
						continue
					}
					err = ErrNextIndex
					break pathloop // clear buffers and return err
				}
				kpar.SetBytes((*[32]byte)(in_privkey[1:33])) // kpar (parent private key) [1 : N-1]
				ki.Add(&kpar)                                // ki = parse256(IL) + kpar (mod n)
				if ki.IsZero() {
					// ki == 0 (probability 1 in N)
					if useSLIP10 {
						// SLIP-0010: "let I = HMAC-SHA512(Key = cpar, Data = 0x01 || IR || ser32(i) and restart at step 2."
						hash.Write([]byte{0x01}) // NB. hash was reset above
						hash.Write(IR[:])
						continue
					}
					err = ErrNextIndex
					break pathloop // clear buffers and return err
				}
				// Note that, as a consequence of BIP-32 rules, ki could equal kpar (probability 1 in N)
				break
			}
			if it < last {
				// write outputs to temporary buffers.
				ki.PutBytesUnchecked(privkey_buf[1:33])
				chaincode_buf = *IR // copy from I_buf
				// use temporary buffers as inputs for next iteration.
				in_privkey = &privkey_buf
				in_chaincode = &chaincode_buf
			} else {
				// last iteration: write outputs to child Bip32Key.
				ki.PutBytesUnchecked(child.pub_priv_key[1:33]) // output child private key
				child.chain_code = *IR                         // output child chain code
				// copy parent's pubkey into the child Bip32Key so we can derive the parent fingerprint later.
				if parent_pub != nil {
					child.parent_pub = parent_pub // from "Public derivation" above
				} else {
					// note: in_privkey is still valid.
					child.parent_pub = ECPubKeyFromECPrivKey((*[32]byte)(in_privkey[1:33])) // serP(K = point(k))
				}
				break
			}
		}
		ki.Zero()                 // clear to avoid leaking key material
		kpar.Zero()               // clear to avoid leaking chaincode material
		memZero(I_buf[:])         // clear to avoid leaking hash material
		memZero(chaincode_buf[:]) // clear to avoid leaking chaincode material
		memZero(privkey_buf[:])   // clear to avoid leaking key material
		if err != nil {
			return &Bip32Key{}, err
		}
		return &child, nil
	} else {
		// Public parent key → This is not possible.
		return &Bip32Key{}, ErrCannotDerive
	}
}

func (key *Bip32Key) PublicCKD(path []uint32, useSLIP10 bool) (*Bip32Key, error) {
	if len(path) > 255 || int(key.depth)+len(path) > 255 {
		// key too deep (encoded as a single byte in WIF)
		return &Bip32Key{}, ErrTooDeep
	}
	if key.keyType == keyBip32Priv {
		// Private parent key → public child key
		// "N(CKDpriv((kpar, cpar), i)) (works always)."
		child, err := key.PrivateCKD(path, useSLIP10)
		if err != nil {
			return &Bip32Key{}, err
		}
		return child.Public(), nil
	} else {
		// Public parent key → public child key
		if len(path) == 0 {
			return key, nil
		}
		// temporary buffers: reused for every path element.
		var I_buf [64]byte
		var chaincode_buf [32]byte
		var idx32 [4]byte
		var err error
		var ILmodN secp256k1.ModNScalar
		var Kpar, pointIL, KiPt secp256k1.JacobianPoint
		KparPub, err := secp256k1.ParsePubKey(key.pub_priv_key[:]) // normalized
		if err != nil {
			// Unlikely: means `key` is invalid.
			return &Bip32Key{}, err
		}
		KparPub.AsJacobian(&Kpar) // in point form, normalized, not ∞ if a valid
		// prepare the output Bip32Key so we can copy into its fields during the last iteration.
		last := len(path) - 1
		child := Bip32Key{
			keyType:      keyBip32Pub,
			depth:        key.depth + byte(len(path)),
			child_number: path[last],
			chain:        key.chain,
		}
		// loop over nodes along the derivation path.
		in_serKpar := &key.pub_priv_key
		in_chaincode := &key.chain_code
	pathloop:
		for it, index := range path {
			// "CKDpub((Kpar, cpar), i) → (Ki, ci) computes a child extended public key from the parent extended public key.
			// It is only defined for non-hardened child keys."
			// Check whether i ≥ 2^31 (whether the child is a hardened key).
			if index&HardenedKey != 0 {
				// hardened child key requested.
				err = ErrHardened
				break
			}
			// Public derivation.
			// "I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i))."
			hash := hmac.New(sha512.New, in_chaincode[:])
			hash.Write(in_serKpar[:]) // serP(Kpar)
			ser32(idx32[:], index)
			var IR *[32]byte
			for {
				hash.Write(idx32[:])     // ser32(i)
				I := hash.Sum(I_buf[:0]) // I aliases I_buf
				hash.Reset()             // clear key material (far too expensive!)
				// "Split I into two 32-byte sequences, IL and IR."
				// Note: (*[32]byte) aliases the underlying array (Go 1.17)
				IL := (*[32]byte)(I[0:32])
				IR = (*[32]byte)(I[32:64])
				// "The returned child key Ki is point(parse256(IL)) + Kpar."
				overflow := ILmodN.SetBytes(IL) // overflow if >= N
				// "In case parse256(IL) ≥ n or Ki is the point at infinity, the resulting key is invalid,"
				// BIP-32: "and one should proceed with the next value for i."
				if overflow != 0 {
					// parse256(IL) ≥ n (probability < 2^-127)
					if useSLIP10 {
						// SLIP-0010: "let I = HMAC-SHA512(Key = cpar, Data = 0x01 || IR || ser32(i) and restart at step 2."
						hash.Write([]byte{0x01}) // NB. hash was reset above
						hash.Write(IR[:])
						continue
					}
					err = ErrNextIndex
					break pathloop // clear buffers and return err
				}
				// note: ILmodN may be zero => pointIL will be the point at infinity
				secp256k1.ScalarBaseMultNonConst(&ILmodN, &pointIL) // pointIL = point(parse256(IL)), normalized
				// note: ∞ + Kpar = Kpar (if pointIL is at ∞) with probability 1 in N
				secp256k1.AddNonConst(&pointIL, &Kpar, &KiPt)                // KiPt = point(parse256(IL)) + Kpar, normalized
				if (KiPt.X.IsZero() && KiPt.Y.IsZero()) || KiPt.Z.IsZero() { // KiPt = ∞ ? (see secp256k1.AddNonConst)
					// Point at infinity (only when pointIL == -Kpar with probability 1 in N)
					if useSLIP10 {
						// SLIP-0010: "let I = HMAC-SHA512(Key = cpar, Data = 0x01 || IR || ser32(i) and restart at step 2."
						hash.Write([]byte{0x01}) // NB. hash was reset above
						hash.Write(IR[:])
						continue
					}
					err = ErrNextIndex
					break pathloop // clear buffers and return err
				}
				KiPt.ToAffine() // requires Z≠0, normalized
				break
			}
			if it < last {
				// use outputs as inputs for next iteration.
				Kpar = KiPt // copy
				Ki := secp256k1.NewPublicKey(&KiPt.X, &KiPt.Y)
				in_serKpar = (*[33]byte)(Ki.SerializeCompressed()) // for next HMAC
				chaincode_buf = *IR                                // copy from I_buf
				in_chaincode = &chaincode_buf
			} else {
				// last iteration: write outputs to child Bip32Key.
				Ki := secp256k1.NewPublicKey(&KiPt.X, &KiPt.Y)
				copy(child.pub_priv_key[:], Ki.SerializeCompressed()) // output child public key
				child.chain_code = *IR                                // output child chain code
				var parent_pub [33]byte = *in_serKpar                 // copy (in_serKpar may alias `key`)
				child.parent_pub = &parent_pub
				break
			}
		}
		memZero(I_buf[:])         // clear to avoid leaking hash material
		memZero(chaincode_buf[:]) // clear to avoid leaking chaincode material
		ILmodN.Zero()             // clear IL hash material
		pointIL.X.Zero()          // clear IL hash material
		pointIL.Y.Zero()          // clear IL hash material
		pointIL.Z.Zero()          // clear IL hash material
		if err != nil {
			return &Bip32Key{}, err
		}
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
	// "Split I into two 32-byte sequences, IL and IR
	// Use parse256(IL) as master secret key, and IR as master chain code."
	masterKey := I[0:32]
	chainCode := I[32:64]
	// "In case parse256(IL) is 0 or parse256(IL) ≥ n, the master key is invalid.
	// The probability of this happening is lower than 2^−127."
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
	if key.depth == 0 {
		if key.parent_fingerprint != 0 {
			return nil, fmt.Errorf("DecodeBip32WIF: invalid key: depth == 0 but fingerprint != 0")
		}
		if key.child_number != 0 {
			return nil, fmt.Errorf("DecodeBip32WIF: invalid key: depth == 0 but child_number != 0")
		}
	}
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
	if key.keyType == keyBip32Priv {
		if key_pre != 0x00 || !ECKeyIsValid((*[32]byte)(key.pub_priv_key[1:33])) {
			key.Clear()
			return nil, fmt.Errorf("DecodeBip32WIF: invalid private key")
		}
	} else {
		if key_pre != 0x02 && key_pre != 0x03 {
			key.Clear()
			return nil, fmt.Errorf("DecodeBip32WIF: invalid public key")
		}
		pub, err := secp256k1.ParsePubKey(key.pub_priv_key[:])
		if err != nil || !pub.IsOnCurve() {
			return nil, fmt.Errorf("DecodeBip32WIF: invalid public key")
		}
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
