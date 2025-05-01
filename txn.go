package doge

// TxHashHex hashes a transaction and returns the hash as a hex-string.
func TxHashHex(txBytes []byte) string {
	hash := DoubleSha256(txBytes)
	reverseInPlace(hash)
	return HexEncode(hash)
}

// TxHashToHex returns the hex-string of a transaction hash.
func TxHashToHex(txHash []byte) string {
	hash := make([]byte, len(txHash))
	copy(hash, txHash) // to avoid mutating the argument.
	reverseInPlace(hash)
	return HexEncode(hash)
}

func reverseInPlace(a []byte) {
	// https://github.com/golang/go/wiki/SliceTricks#reversing
	for left, right := 0, len(a)-1; left < right; left, right = left+1, right-1 {
		a[left], a[right] = a[right], a[left]
	}
}
