package doge

const (
	VersionAuxPoW = 256
	CoinbaseVOut  = 0xffffffff
)

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
	TxID     string // hex, computed from tx data
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

func DecodeBlock(blockBytes []byte) (Block, bool) {
	s := NewStream(blockBytes)
	return readBlock(s), s.Complete()
}

func readBlock(s *Stream) (b Block) {
	b.Header = readHeader(s)
	if b.Header.IsAuxPoW() {
		b.AuxPoW = readMerkleTx(s)
	}
	numTx := s.VarUint()
	for i := uint64(0); i < numTx; i++ {
		b.Tx = append(b.Tx, readTx(s))
	}
	return
}

func readHeader(s *Stream) (b BlockHeader) {
	b.Version = s.Uint32le()
	b.PrevBlock = s.Bytes(32)
	b.MerkleRoot = s.Bytes(32)
	b.Timestamp = s.Uint32le()
	b.Bits = s.Uint32le()
	b.Nonce = s.Uint32le()
	return
}

func readMerkleTx(s *Stream) *MerkleTx {
	var m MerkleTx
	m.CoinbaseTx = readTx(s)
	m.ParentHash = s.Bytes(32)
	m.CoinbaseBranch = readMerkleBranch(s)
	m.BlockchainBranch = readMerkleBranch(s)
	m.ParentBlock = readHeader(s)
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

func DecodeTx(txBytes []byte) (BlockTx, bool) {
	s := NewStream(txBytes)
	return readTx(s), s.Complete()
}

func readTx(s *Stream) (tx BlockTx) {
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
	if s.Valid() {
		tx.TxID = TxHashHex(s.buf[start:s.pos])
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
