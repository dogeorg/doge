package doge

// TxHashHex hashes a transaction and returns the hash as a hex-string.
func TxHashHex(txBytes []byte) string {
	hash := DoubleSha256(txBytes)
	reverseBytes(hash, hash) // reverse in-place
	return HexEncode(hash)
}

// TxHashToHex returns the hex-string of a transaction hash.
func TxHashToHex(hash []byte) string {
	return HexEncodeReversed(hash)
}

// reverseBytes reverses a byte slice (`from` and `to` may alias for in-place reverse)
func reverseBytes(from []byte, to []byte) {
	// https://github.com/golang/go/wiki/SliceTricks#reversing
	left, right := 0, len(from)-1
	for ; left < right; left, right = left+1, right-1 {
		to[left], to[right] = from[right], from[left]
	}
	if left == right { // for copy-case with odd number of bytes
		to[left] = from[left]
	}
}
