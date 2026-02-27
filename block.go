package doge

import (
	"errors"
	"fmt"
	"log"
)

const (
	VersionAuxPoW = 256
	CoinbaseVOut  = 0xffffffff
	MaxScriptSize = 10_000     // MAX_SCRIPT_SIZE from Dogecoin Core (script.h)
	MaxVarIntSize = 0x02000000 // MAX_SIZE from Dogecoin Core (serialize.h)
)

type HashID []byte

func (id HashID) ToHex() string {
	return TxHashToHex(id)
}

var CoinbaseTxID = [32]byte{}

type Block struct {
	Header BlockHeader
	AuxPoW *MerkleTx // if IsAuxPoW()
	Tx     []BlockTx
}

type BlockHeader struct {
	Version    uint32
	PrevBlock  []byte // 32 bytes
	MerkleRoot []byte // 32 bytes
	Timestamp  uint32
	Bits       uint32
	Nonce      uint32
	BlockID    HashID // Block Hash (if decoded with calcHash=True)
}

func (b *BlockHeader) IsAuxPoW() bool {
	return (b.Version & VersionAuxPoW) != 0
}

type MerkleTx struct {
	CoinbaseTx       BlockTx
	ParentHash       []byte // 32 bytes
	CoinbaseBranch   MerkleBranch
	BlockchainBranch MerkleBranch
	ParentBlock      BlockHeader
}

type MerkleBranch struct {
	Hash     [][]byte // 32 bytes each
	SideMask uint32
}

type BlockTx struct {
	Version  uint32
	VIn      []BlockTxIn
	VOut     []BlockTxOut
	LockTime uint32
	TxID     HashID // Transaction Hash (if decoded with calcHash=True)
}

type BlockTxIn struct {
	TxID     []byte // 32 bytes
	VOut     uint32
	Script   []byte // varied length
	Sequence uint32
	Witness  [][]byte // varied length, for SegWit transactions
}

type BlockTxOut struct {
	Value  int64
	Script []byte // varied length
}

// DecodeBlock decodes a block from a byte slice (original API)
// If calcHash is true, the block hash is calculated and stored in the Block.BlockID field.
// Returns false if the serialized block data is malformed.
func DecodeBlock(blockBytes []byte, calcHash bool) (Block, bool) {
	b, err := DecodeBlockErr(blockBytes, calcHash)
	return b, err == nil
}

// DecodeBlockErr decodes a block from a byte slice (enhanced API)
// If calcHash is true, the block hash is calculated and stored in the Block.BlockID field.
// Returns an error if the serialized block data is malformed.
func DecodeBlockErr(blockBytes []byte, calcHash bool) (Block, error) {
	s := NewStream(blockBytes)
	b, err := readBlock(s, calcHash)
	if err == nil && !s.Complete() {
		if !s.Valid() {
			err = fmt.Errorf("invalid block: truncated / incomplete block (at %v of %v)", s.pos, s.len)
		} else {
			err = fmt.Errorf("invalid block: unexpected data at end of block (at %v of %v)", s.pos, s.len)
		}
	}
	return b, err
}

func readBlock(s *Stream, calcHash bool) (b Block, err error) {
	b.Header = readHeader(s, calcHash)
	if !s.Valid() {
		return b, fmt.Errorf("invalid block: unexpected end of block in header (at %v of %v)", s.pos, s.len)
	}
	if b.Header.IsAuxPoW() {
		mtx, err := readMerkleTx(s, calcHash)
		if err != nil {
			return b, fmt.Errorf("invalid block: %v", err)
		}
		b.AuxPoW = mtx
	}
	numTx := s.VarUint()
	for i := uint64(0); i < numTx; i++ {
		tx, err := readTx(s, calcHash)
		if err != nil {
			return b, fmt.Errorf("invalid block: bad tx %v of %v: %v", i, numTx, err)
		}
		if !s.Valid() {
			return b, fmt.Errorf("invalid block: unexpected end of block in tx %v of %v: %v", i, numTx, err)
		}
		b.Tx = append(b.Tx, tx)
	}
	return
}

func readHeader(s *Stream, calcHash bool) (b BlockHeader) {
	start := s.pos
	b.Version = s.Uint32le()
	b.PrevBlock = s.Bytes(32)
	b.MerkleRoot = s.Bytes(32)
	b.Timestamp = s.Uint32le()
	b.Bits = s.Uint32le()
	b.Nonce = s.Uint32le()
	// Compute Block hash from header bytes.
	if calcHash && s.Valid() {
		b.BlockID = DoubleSha256(s.buf[start:s.pos])
	}
	return
}

func readMerkleTx(s *Stream, calcHash bool) (*MerkleTx, error) {
	var m MerkleTx
	tx, err := readTx(s, calcHash)
	if err != nil {
		return nil, fmt.Errorf("invalid merkle tx: %v", err)
	}
	m.CoinbaseTx = tx
	m.ParentHash = s.Bytes(32)
	m.CoinbaseBranch = readMerkleBranch(s)
	m.BlockchainBranch = readMerkleBranch(s)
	m.ParentBlock = readHeader(s, calcHash)
	return &m, nil
}

func readMerkleBranch(s *Stream) (b MerkleBranch) {
	numHash := s.VarUint()
	for i := uint64(0); i < numHash; i++ {
		b.Hash = append(b.Hash, s.Bytes(32))
	}
	b.SideMask = s.Uint32le()
	return
}

// DecodeTx decodes a transaction from a byte slice (original API)
// If calcHash is true, the transaction hash is calculated and stored in the BlockTx.TxID field.
// Returns false if the serialized tx data is malformed.
func DecodeTx(txBytes []byte, calcHash bool) (BlockTx, bool) {
	tx, err := DecodeTxErr(txBytes, calcHash)
	return tx, err == nil
}

// DecodeTxErr decodes a transaction from a byte slice (enhanced API)
// If calcHash is true, the transaction hash is calculated and stored in the BlockTx.TxID field.
// Returns an error if the serialized transaction data is malformed.
func DecodeTxErr(txBytes []byte, calcHash bool) (BlockTx, error) {
	s := NewStream(txBytes)
	tx, err := readTx(s, calcHash)
	if err == nil && !s.Complete() {
		if !s.Valid() {
			err = fmt.Errorf("invalid transaction: truncated / incomplete transaction (at %v of %v)", s.pos, s.len)
		} else {
			err = fmt.Errorf("invalid transaction: unexpected data at end of transaction (at %v of %v)", s.pos, s.len)
		}
	}
	return tx, err
}

func readTx(s *Stream, calcHash bool) (tx BlockTx, err error) {
	markerFound := false
	skippedVinVout := false
	flags := uint8(0)
	startOfTx := s.pos
	tx.Version = s.Uint32le()
	beforeWitnessFlag := s.pos
	afterWitnessFlag := s.pos
	// Detect extended transaction serialization format: "The marker MUST be a 1-byte zero value: 0x00"
	// However, Core uses ReadCompactSize via `s >> tx.vin` in UnserializeTransaction, so anything goes.
	// The following nested if-else structure exactly mirrors Core.
	tx_in := s.VarUint()
	if tx_in == 0 {
		// "The flag MUST be a 1-byte non-zero value. Currently, 0x01 MUST be used."
		// However, Core checks for != 0, so we do too (bug?).
		markerFound = true
		flags = s.Bytes(1)[0]
		afterWitnessFlag = s.pos
		if flags != 0 {
			// Here Core parses full VIn and VOut vectors.
			tx_in = s.VarUint()
			tx.VIn, tx.VOut, err = readVinVout(s, tx_in)
			if err != nil {
				return tx, err
			}
		} else {
			// VIn/VOut parsing is skipped entirely if flags is zero! (as per Core)
			// This may be an oversight in Core - probably an exploit.
			skippedVinVout = true
		}
	} else {
		// We read a non-empty vin. Assume a normal vin/vout follows (as per Core)
		tx.VIn, tx.VOut, err = readVinVout(s, tx_in)
		if err != nil {
			return tx, err
		}
	}
	// Here Core tests if the low bit is set.
	beforeWitnessData := s.pos
	if (flags & 1) != 0 {
		// The witness flag is present: read witness data.
		// Core parses `std::vector<std::vector<unsigned char>>` per vin.
		flags ^= 1 // Core toggles the low bit.
		for i := uint64(0); i < tx_in; i++ {
			numStackItems := s.VarUint()
			for k := uint64(0); k < numStackItems; k++ {
				itemLen := s.VarUint()
				if itemLen > MaxVarIntSize {
					return tx, fmt.Errorf("invalid transaction: witness data too large: %v for vin %v stack item %v", itemLen, i, k)
				}
				itemData := s.Bytes(itemLen)
				tx.VIn[i].Witness = append(tx.VIn[i].Witness, itemData)
			}
		}
	}
	// Here Core treats non-zero flags as an error.
	if flags != 0 {
		return tx, fmt.Errorf("invalid transaction: unknown transaction optional data: %v", flags)
	}
	afterWitnessData := s.pos
	tx.LockTime = s.Uint32le()
	// Compute TX hash from transaction bytes.
	if calcHash && s.Valid() {
		endOfTx := s.pos
		if markerFound {
			// Extended serialization: txid = hash(version | (no marker+flag) | vin/vout | (no witness) | locktime)
			lenSeg1 := beforeWitnessFlag - startOfTx
			lenSeg2 := beforeWitnessData - afterWitnessFlag
			lenSeg3 := endOfTx - afterWitnessData
			total := int(lenSeg1 + lenSeg2 + lenSeg3)
			buf := make([]byte, total)
			copy(buf, s.buf[startOfTx:beforeWitnessFlag])
			copy(buf[lenSeg1:], s.buf[afterWitnessFlag:beforeWitnessData])
			copy(buf[lenSeg1+lenSeg2:], s.buf[afterWitnessData:endOfTx])
			tx.TxID = DoubleSha256(buf)
		} else {
			// No witness marker: txid is the hash of the entire transaction
			tx.TxID = DoubleSha256(s.buf[int(startOfTx):int(endOfTx)])
		}
		if skippedVinVout {
			// Core skips VIn/Vout parsing entirely if flags is zero (bug?)
			log.Printf("[!] WARNING: skipped VIn/Vout parsing entirely, as per Core implementation (bug?): %v", TxHashToHex(tx.TxID))
		}
	}
	return tx, nil
}

func readVinVout(s *Stream, tx_in uint64) (VIn []BlockTxIn, VOut []BlockTxOut, err error) {
	for i := uint64(0); i < tx_in; i++ {
		vin, err := readTxIn(s)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading tx input %d: %v", i, err)
		}
		VIn = append(VIn, vin)
	}
	tx_out := s.VarUint()
	for i := uint64(0); i < tx_out; i++ {
		vout, err := readTxOut(s)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading tx output %d: %v", i, err)
		}
		VOut = append(VOut, vout)
	}
	return
}

func readTxIn(s *Stream) (in BlockTxIn, err error) {
	in.TxID = s.Bytes(32)
	in.VOut = s.Uint32le()
	scriptLen := s.VarUint()
	if scriptLen > MaxScriptSize {
		return in, fmt.Errorf("script length %d exceeds maximum allowed size of %d", scriptLen, MaxScriptSize)
	}
	in.Script = s.Bytes(uint64(scriptLen))
	in.Sequence = s.Uint32le()
	return in, nil
}

func readTxOut(s *Stream) (out BlockTxOut, err error) {
	out.Value = int64(s.Uint64le())
	scriptLen := s.VarUint()
	if scriptLen > MaxScriptSize {
		return out, fmt.Errorf("script length %d exceeds maximum allowed size of %d", scriptLen, MaxScriptSize)
	}
	out.Script = s.Bytes(uint64(scriptLen))
	return out, nil
}

// EncodeTx encodes a transaction to a byte slice.
// This function does not fail (Go panics if out of memory).
func EncodeTx(tx BlockTx) ([]byte, error) {
	encoder := Encode(10 + len(tx.VIn)*66 + len(tx.VOut)*33)
	encoder.UInt32(tx.Version) // tx.Version
	if len(tx.VIn) < 1 || len(tx.VOut) < 1 {
		return nil, errors.New("EncodeTx: must have at least one input and one output")
	}
	encoder.VarUInt(uint64(len(tx.VIn))) // num_tx_in
	for _, vin := range tx.VIn {
		if len(vin.TxID) != 32 {
			return nil, errors.New("EncodeTx: wrong TxID length")
		}
		encoder.Bytes(vin.TxID)                  // in.TxID       32
		encoder.UInt32(vin.VOut)                 // in.VOut       4
		encoder.VarUInt(uint64(len(vin.Script))) // script_len    1
		encoder.Bytes(vin.Script)                // in.Script     33 (P2PKH)
		encoder.UInt32(vin.Sequence)             // in.Sequence   4
	}
	encoder.VarUInt(uint64(len(tx.VOut))) // num_tx_out
	for _, vout := range tx.VOut {
		encoder.Int64(vout.Value) // out.Value    8
		if len(vout.Script) < 1 {
			return nil, errors.New("EncodeTx: output script cannot be empty")
		}
		encoder.VarUInt(uint64(len(vout.Script))) // script_len   1
		encoder.Bytes(vout.Script)                // out.Script   25 (P2PKH)
	}
	encoder.UInt32(tx.LockTime) // tx.LockTime
	return encoder.Result(), nil
}
