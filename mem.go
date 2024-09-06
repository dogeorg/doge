package doge

var arrayOfZeroBytes [128]byte // 128 zero-bytes (1-2 cache lines)

func memZero(slice []byte) {
	n := copy(slice, arrayOfZeroBytes[:])
	for n < len(slice) {
		n += copy(slice[n:], arrayOfZeroBytes[:])
	}
}
