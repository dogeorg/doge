package doge

import "errors"

const MAX_OP_RETURN_RELAY = 83 // from Core IsStandard in policy.cpp

// ScriptType is inferred from the script by pattern-matching the bytecode
type ScriptType byte

// ScriptType constants (must fit in a single byte for compact storage)
const (
	ScriptTypeNone        ScriptType = 0 // No Script (reserved)
	ScriptTypeP2PK        ScriptType = 1 // TX_PUBKEY (in Core)
	ScriptTypeP2PKH       ScriptType = 2 // TX_PUBKEYHASH
	ScriptTypeP2SH        ScriptType = 3 // TX_SCRIPTHASH
	ScriptTypeMultiSig    ScriptType = 4 // TX_MULTISIG
	ScriptTypeP2PKHW      ScriptType = 5 // TX_WITNESS_V0_KEYHASH
	ScriptTypeP2SHW       ScriptType = 6 // TX_WITNESS_V0_SCRIPTHASH
	ScriptTypeNullData    ScriptType = 7 // TX_NULL_DATA
	ScriptTypeNonStandard ScriptType = 8 // TX_NONSTANDARD
)

// ScriptHashOrData is the PubKeyHash, ScriptHash, PubKey, MultiSig PubKeys, or OP_RETURN data
// extracted from the script by ClassifyScript
type ScriptHashOrData = []byte

// ClassifyScript infers ScriptType from a script by pattern-matching the bytecode
// Returns the PubKeyHash/ScriptHash/PubKey/Data extracted from the script
func ClassifyScript(script []byte) (ScriptType, ScriptHashOrData) {
	L := len(script)
	// P2PKH: OP_DUP OP_HASH160 <pubKeyHash:20> OP_EQUALVERIFY OP_CHECKSIG (25)
	if L == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] == 20 &&
		script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG {
		return ScriptTypeP2PKH, script[3:23] // 20 bytes PubKey Hash (view)
	}
	// P2PK: <compressedPubKey:33> OP_CHECKSIG
	if L == 35 && script[0] == 33 && script[34] == OP_CHECKSIG {
		return ScriptTypeP2PK, script[1:34] // 33 bytes Compressed PubKey (view)
	}
	// P2PK: <uncompressedPubKey:65> OP_CHECKSIG
	if L == 67 && script[0] == 65 && script[66] == OP_CHECKSIG {
		return ScriptTypeP2PK, script[1:66] // 65 bytes PubKey (view)
	}
	// P2SH: OP_HASH160 0x14 <hash> OP_EQUAL
	if L == 23 && script[0] == OP_HASH160 && script[1] == 20 && script[22] == OP_EQUAL {
		return ScriptTypeP2SH, script[2:22] // 20 bytes Script Hash (view)
	}
	// OP_RETURN
	if L > 0 && script[0] == OP_RETURN && L <= MAX_OP_RETURN_RELAY {
		// Standard: script length <= MAX_OP_RETURN_RELAY from Core IsStandard in policy.cpp
		return ScriptTypeNullData, script[1:] // bytes of Data with length-prefix-byte, potentially multiple
	}
	// OP_m <pubkey*n> OP_n OP_CHECKMULTISIG (or a non-standard script)
	if L >= 3+34 && script[L-1] == OP_CHECKMULTISIG && IsOP_N(script[L-2]) && IsOP_N(script[0]) {
		N_Keys := DecodeOP_N(script[L-2])
		M_Keys := DecodeOP_N(script[0])
		// Standard: N >= 1 && N <= 3 && M >= 1 && M <= N from Core IsStandard in policy.cpp
		if N_Keys >= 1 && N_Keys <= 3 && M_Keys >= 1 && M_Keys <= N_Keys {
			endOfKeys := L - 2 // first byte after key data
			ofs := 1
			for ofs < endOfKeys && N_Keys > 0 {
				if script[ofs] == 65 && ofs+66 <= endOfKeys {
					ofs += 66 // uncompressed public key
				} else if script[ofs] == 33 && ofs+34 <= endOfKeys {
					ofs += 34 // compressed public key
				} else {
					ofs = 0
					break // non-standard multisig script
				}
				N_Keys -= 1
			}
			if ofs == endOfKeys && N_Keys == 0 { // used all data + all N keys found
				// standard multisig script
				return ScriptTypeMultiSig, script[0 : L-1] // all pubkeys with length-prefix-byte
			}
		}
		// Otherwise a non-standard script that "looks like" multisig: fall through
	}
	// Non-standard script
	return ScriptTypeNonStandard, script
}

// isOP_N recognises OP_1 to OP_16
func IsOP_N(op byte) bool {
	return (op >= OP_1 && op <= OP_16)
}

// decodeOP_N decodes the pushed literal from OP_1 to OP_16
func DecodeOP_N(op byte) int {
	return int(op - (OP_1 - 1)) // same as (op - OP_1) + 1
}

// DecodePushOP decodes the 'length' from OP_0, OP_1 to OP_16, OP_PUSHDATA1,2,4
func DecodePushOP(script []byte, ofs int) (newOfs int, length uint32, ok bool) {
	if ofs >= len(script) {
		return ofs, 0, false // end of script
	}
	opcode := script[ofs]
	if opcode < OP_PUSHDATA1 {
		return ofs + 1, uint32(opcode), true // 0x00..0x4b push data of `opcode` length (0-75)
	}
	if opcode == OP_PUSHDATA1 && ofs+1 < len(script) {
		return ofs + 2, uint32(script[ofs+1]), true
	}
	if opcode == OP_PUSHDATA2 && ofs+2 < len(script) {
		return ofs + 3, uint32(script[ofs+2])<<8 | uint32(script[ofs+1]), true
	}
	if opcode == OP_PUSHDATA4 && ofs+4 < len(script) {
		return ofs + 5, uint32(script[ofs+4])<<24 | uint32(script[ofs+3])<<16 | uint32(script[ofs+2])<<8 | uint32(script[ofs+1]), true
	}
	return ofs, 0, false // end of script or not a PUSH opcode
}

// ExpandScript re-creates the ScriptPubKey from a ScriptType and ScriptHashOrData
func ExpandScript(typ ScriptType, data ScriptHashOrData) (script []byte) {
	switch typ {
	case ScriptTypeP2PK: // TX_PUBKEY
		if len(data) == 33 {
			// 33 bytes Compressed PubKey
			script = make([]byte, 35)
			script[0] = 33
			copy(script[1:34], data)
			script[34] = OP_CHECKSIG
			return script
		}
		if len(data) == 65 {
			// 65 bytes PubKey
			script = make([]byte, 67)
			script[0] = 65
			copy(script[1:66], data)
			script[66] = OP_CHECKSIG
			return script
		}

	case ScriptTypeP2PKH: // TX_PUBKEYHASH
		script = make([]byte, 25)
		script[0] = OP_DUP
		script[1] = OP_HASH160
		script[2] = 20
		copy(script[3:23], data) // 20 bytes PubKey Hash
		script[23] = OP_EQUALVERIFY
		script[24] = OP_CHECKSIG
		return script

	case ScriptTypeP2SH: // TX_SCRIPTHASH
		script = make([]byte, 23)
		script[0] = OP_HASH160
		script[1] = 20
		copy(script[2:22], data) // 20 bytes Script Hash
		script[22] = OP_EQUAL
		return script

	case ScriptTypeMultiSig: // TX_MULTISIG
		script = make([]byte, len(data)+1)
		copy(script, data)
		script[len(data)] = OP_CHECKMULTISIG
		return script

	case ScriptTypeNullData: // TX_NULL_DATA
		script = make([]byte, len(data)+1)
		script[0] = OP_RETURN
		copy(script[1:], data)
		return script

	case ScriptTypeNonStandard: // TX_NONSTANDARD
		return data

	default:
	}
	return nil
}

// P2PKHScriptFromAddress creates a P2PKH script from a Dogecoin address.
// Returns the script or an error if the address is invalid.
func P2PKHScriptFromAddress(address Address) ([]byte, error) {
	pubKeyHash, err := Base58DecodeCheck(string(address))
	if err != nil {
		return nil, errors.New("P2PKHScriptFromAddress: invalid address")
	}
	return P2PKHScript(pubKeyHash[1:]) // remove version byte
}

// P2PKHScript creates a P2PKH script from a pubKeyHash.
// Returns the script or an error if the pubKeyHash length is invalid.
func P2PKHScript(pubKeyHash []byte) ([]byte, error) {
	if len(pubKeyHash) != 20 {
		return nil, errors.New("P2PKHScript: invalid pubKeyHash length")
	}
	script := make([]byte, 25)
	script[0] = OP_DUP
	script[1] = OP_HASH160
	script[2] = 20
	copy(script[3:23], pubKeyHash)
	script[23] = OP_EQUALVERIFY
	script[24] = OP_CHECKSIG
	return script, nil
}

// P2SHScriptFromRedeemScript creates a P2SH script from a redeem script.
// Returns the script or an error if the redeem script length is invalid.
func P2SHScriptFromRedeemScript(redeemScript []byte) ([]byte, error) {
	scriptHash := Hash160(redeemScript)
	return P2SHScript(scriptHash)
}

// P2SHScript creates a P2SH script from a redeem script hash.
// Returns the script or an error if the hash length is invalid.
func P2SHScript(scriptHash []byte) ([]byte, error) {
	if len(scriptHash) != 20 {
		return nil, errors.New("P2SHScript: invalid scriptHash length")
	}
	script := make([]byte, 23)
	script[0] = OP_HASH160
	script[1] = 20
	copy(script[2:22], scriptHash)
	script[22] = OP_EQUAL
	return script, nil
}
