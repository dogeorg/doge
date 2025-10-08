package doge

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHex(t *testing.T) {
	data := []byte("\x00\x01Hello\xffWorld!\x0d\x0a")
	hex := HexEncode(data)
	if hex != "000148656c6c6fff576f726c64210d0a" {
		t.Errorf("HexEncode: wrong hex: " + hex)
	}
	out, err := HexDecode(hex)
	if err != nil {
		t.Errorf("HexDecode: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("HexDecode: decoded bytes don't match: %v vs %v", out, data)
	}
}

func TestHexEncodeReversed(t *testing.T) {
	original := []byte("\x00\x01Hello\xffWorld!\x0d\x0a")
	manually_reversed := []byte("\x0a\x0d!dlroW\xffolleH\x01\x00")
	reversed := HexEncodeReversed(original)
	rbytes, err := hex.DecodeString(reversed)
	if err != nil {
		t.Errorf("HexEncodeReversed: %v", err)
	}
	if !bytes.Equal(rbytes, manually_reversed) {
		t.Errorf("HexEncodeReversed: bytes don't match manually reversed copy: %x vs %x", rbytes, manually_reversed)
	}
	decoded, err := HexDecodeReversed(reversed)
	if err != nil {
		t.Errorf("HexDecodeReversed: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Errorf("HexDecodeReversed: bytes don't round-trip: %x vs %x", decoded, original)
	}
}

// Test Heplers

func hx2b(str string) (bytes []byte) {
	bytes, err := HexDecode(str)
	if err != nil {
		panic("WIF: bad fixture: " + str)
	}
	return
}
