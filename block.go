package doge

import "errors"

const (
	VersionAuxPoW = 256
	CoinbaseVOut  = 0xffffffff
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
}

type BlockTxOut struct {
	Value  int64
	Script []byte // varied length
}

// DecodeBlock decodes a block from a byte slice.
// If calcHash is true, the block hash is calculated and stored in the Block.BlockID field.
// Returns false if the serialized block data is malformed.
func DecodeBlock(blockBytes []byte, calcHash bool) (Block, bool) {
	s := NewStream(blockBytes)
	return readBlock(s, calcHash), s.Complete()
}

func readBlock(s *Stream, calcHash bool) (b Block) {
	b.Header = readHeader(s, calcHash)
	if b.Header.IsAuxPoW() {
		b.AuxPoW = readMerkleTx(s, calcHash)
	}
	numTx := s.VarUint()
	for i := uint64(0); i < numTx; i++ {
		b.Tx = append(b.Tx, readTx(s, calcHash))
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

func readMerkleTx(s *Stream, calcHash bool) *MerkleTx {
	var m MerkleTx
	m.CoinbaseTx = readTx(s, calcHash)
	m.ParentHash = s.Bytes(32)
	m.CoinbaseBranch = readMerkleBranch(s)
	m.BlockchainBranch = readMerkleBranch(s)
	m.ParentBlock = readHeader(s, calcHash)
	return &m
}

func readMerkleBranch(s *Stream) (b MerkleBranch) {
	numHash := s.VarUint()
	for i := uint64(0); i < numHash; i++ {
		b.Hash = append(b.Hash, s.Bytes(32))
	}
	b.SideMask = s.Uint32le()
	return
}

// DecodeTx decodes a transaction from a byte slice.
// If calcHash is true, the transaction hash is calculated and stored in the BlockTx.TxID field.
// Returns false if the serialized transaction data is malformed.
func DecodeTx(txBytes []byte, calcHash bool) (BlockTx, bool) {
	s := NewStream(txBytes)
	return readTx(s, calcHash), s.Complete()
}

func readTx(s *Stream, calcHash bool) (tx BlockTx) {
	start := s.pos
	tx.Version = s.Uint32le()
	num_tx_in := s.VarUint()
	for i := uint64(0); i < num_tx_in; i++ {
		tx.VIn = append(tx.VIn, readTxIn(s))
	}
	num_tx_out := s.VarUint()
	for i := uint64(0); i < num_tx_out; i++ {
		tx.VOut = append(tx.VOut, readTxOut(s))
	}
	tx.LockTime = s.Uint32le()
	// Compute TX hash from transaction bytes.
	if calcHash && s.Valid() {
		tx.TxID = DoubleSha256(s.buf[start:s.pos])
	}
	return
}

func readTxIn(s *Stream) (in BlockTxIn) {
	in.TxID = s.Bytes(32)
	in.VOut = s.Uint32le()
	script_len := s.VarUint()
	in.Script = s.Bytes(script_len)
	in.Sequence = s.Uint32le()
	return
}

func readTxOut(s *Stream) (out BlockTxOut) {
	out.Value = int64(s.Uint64le())
	script_len := s.VarUint()
	out.Script = s.Bytes(script_len)
	return
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
		if len(vin.Script) < 1 {
			return nil, errors.New("EncodeTx: invalid script length")
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
			return nil, errors.New("EncodeTx: invalid script length")
		}
		encoder.VarUInt(uint64(len(vout.Script))) // script_len   1
		encoder.Bytes(vout.Script)                // out.Script   25 (P2PKH)
	}
	encoder.UInt32(tx.LockTime) // tx.LockTime
	return encoder.Result(), nil
}
