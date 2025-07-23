package doge

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

func DecodeTx(txBytes []byte, calcHash bool) (BlockTx, bool) {
	s := NewStream(txBytes)
	return readTx(s, calcHash), s.Complete()
}

func readTx(s *Stream, calcHash bool) (tx BlockTx) {
	start := s.pos
	tx.Version = s.Uint32le()
	tx_in := s.VarUint()
	for i := uint64(0); i < tx_in; i++ {
		tx.VIn = append(tx.VIn, readTxIn(s))
	}
	tx_out := s.VarUint()
	for i := uint64(0); i < tx_out; i++ {
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
