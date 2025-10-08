package doge

import (
	"encoding/hex"
)

func HexEncode(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

func HexEncodeReversed(data []byte) string {
	b := make([]byte, len(data))
	reverseBytes(data, b) // copy reversed
	return hex.EncodeToString(b)
}

func HexDecode(str string) ([]byte, error) {
	return hex.DecodeString(str)
}

func HexDecodeReversed(str string) ([]byte, error) {
	b, err := hex.DecodeString(str)
	if err != nil {
		return b, err
	}
	reverseBytes(b, b) // reverse in-place
	return b, nil
}

func IsValidHex(hex string) bool {
	// eh, this will do.
	_, err := HexDecode(hex)
	return err == nil
}
