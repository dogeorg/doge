package doge

import (
	"bytes"
	"testing"
)

func TestDecodeBytes(t *testing.T) {
	stream := Decode(hx2b("01020304"))
	if !bytes.Equal(stream.Bytes(4), hx2b("01020304")) {
		t.Errorf("Bytes: wrong value: %x", stream.Bytes(2))
	}
	if !stream.Complete() {
		t.Errorf("Bytes: stream not complete")
	}
}

func TestDecodeUInt16(t *testing.T) {
	stream := Decode(hx2b("0102"))
	if stream.UInt16() != 0x0201 {
		t.Errorf("UInt16: wrong value: %x", stream.UInt16())
	}
	if !stream.Complete() {
		t.Errorf("UInt16: stream not complete")
	}
}

func TestDecodeUInt32(t *testing.T) {
	stream := Decode(hx2b("01020304"))
	if stream.UInt32() != 0x04030201 {
		t.Errorf("UInt32: wrong value: %x", stream.UInt32())
	}
	if !stream.Complete() {
		t.Errorf("UInt32: stream not complete")
	}
}

func TestDecodeUInt64(t *testing.T) {
	stream := Decode(hx2b("0102030405060708"))
	if stream.UInt64() != 0x0807060504030201 {
		t.Errorf("UInt64: wrong value: %x", stream.UInt64())
	}
	if !stream.Complete() {
		t.Errorf("UInt64: stream not complete")
	}
}

func TestDecodeVarUint(t *testing.T) {
	// Test VarUint with 1 byte
	stream := Decode(hx2b("01"))
	if stream.VarUInt() != 0x01 {
		t.Errorf("VarUInt: wrong value: %x", stream.VarUInt())
	}
	if !stream.Complete() {
		t.Errorf("VarUInt: stream not complete")
	}
}

func TestDecodeVarUint2(t *testing.T) {
	// Test VarUint with 2 bytes
	stream := Decode(hx2b("FD0102"))
	if stream.VarUInt() != 0x0201 {
		t.Errorf("VarUInt: wrong value: %x", stream.VarUInt())
	}
	if !stream.Complete() {
		t.Errorf("VarUInt: stream not complete")
	}
}

func TestDecodeVarUint3(t *testing.T) {
	// Test VarUint with 4 bytes
	stream := Decode(hx2b("FE01020304"))
	if stream.VarUInt() != 0x04030201 {
		t.Errorf("VarUInt: wrong value: %x", stream.VarUInt())
	}
	if !stream.Complete() {
		t.Errorf("VarUInt: stream not complete")
	}
}

func TestDecodeVarUint4(t *testing.T) {
	// Test VarUint with 8 bytes
	stream := Decode(hx2b("FF0102030405060708"))
	if stream.VarUInt() != 0x0807060504030201 {
		t.Errorf("VarUInt: wrong value: %x", stream.VarUInt())
	}
	if !stream.Complete() {
		t.Errorf("VarUInt: stream not complete")
	}
}

func TestDecodeOverrunBytes(t *testing.T) {
	// Test overrun of bytes
	stream := Decode(hx2b("01020304"))
	if stream.Bytes(5) != nil {
		t.Errorf("Bytes: should return nil for overrun")
	}
	if stream.Valid() {
		t.Errorf("Bytes: stream should not be valid for overrun")
	}
	if stream.Complete() {
		t.Errorf("Bytes: stream should not be complete for overrun")
	}
}

func TestDecodeOverrunUInt16(t *testing.T) {
	// Test overrun of UInt16
	stream := Decode(hx2b("01"))
	if stream.UInt16() != 0 {
		t.Errorf("UInt16: stream should return 0 for overrun")
	}
	if stream.Valid() {
		t.Errorf("UInt16: stream should not be valid for overrun")
	}
	if stream.Complete() {
		t.Errorf("UInt16: stream should not be complete for overrun")
	}
}

func TestDecodeOverrunUInt32(t *testing.T) {
	// Test overrun of UInt32
	stream := Decode(hx2b("010203"))
	if stream.UInt32() != 0 {
		t.Errorf("UInt32: stream should return 0 for overrun")
	}
	if stream.Valid() {
		t.Errorf("UInt32: stream should not be valid for overrun")
	}
	if stream.Complete() {
		t.Errorf("UInt32: stream should not be complete for overrun")
	}
}

func TestDecodeOverrunUInt64(t *testing.T) {
	// Test overrun of UInt64
	stream := Decode(hx2b("01020304050607"))
	if stream.UInt64() != 0 {
		t.Errorf("UInt64: stream should return 0 for overrun")
	}
	if stream.Valid() {
		t.Errorf("UInt64: stream should not be valid for overrun")
	}
	if stream.Complete() {
		t.Errorf("UInt64: stream should not be complete for overrun")
	}
}

func TestDecodeOverrunVarUInt(t *testing.T) {
	// Test overrun of VarUInt
	stream := Decode([]byte{})
	if stream.VarUInt() != 0 {
		t.Errorf("VarUInt: should return 0 for overrun")
	}
	if stream.Valid() {
		t.Errorf("VarUInt: stream should not be valid for overrun")
	}
	if stream.Complete() {
		t.Errorf("VarUInt: stream should not be complete for overrun")
	}
}

func TestDecodeBool(t *testing.T) {
	// Test Bool with true value
	stream := Decode(hx2b("01"))
	if !stream.Bool() {
		t.Errorf("Bool: wrong value: expected true, got false")
	}
	if !stream.Complete() {
		t.Errorf("Bool: stream not complete")
	}
}

func TestDecodeBoolFalse(t *testing.T) {
	// Test Bool with false value
	stream := Decode(hx2b("00"))
	if stream.Bool() {
		t.Errorf("Bool: wrong value: expected false, got true")
	}
	if !stream.Complete() {
		t.Errorf("Bool: stream not complete")
	}
}

func TestDecodeUInt8(t *testing.T) {
	stream := Decode(hx2b("42"))
	if stream.UInt8() != 0x42 {
		t.Errorf("UInt8: wrong value: %x", stream.UInt8())
	}
	if !stream.Complete() {
		t.Errorf("UInt8: stream not complete")
	}
}

func TestDecodeInt64(t *testing.T) {
	stream := Decode(hx2b("0102030405060708"))
	if stream.Int64() != 0x0807060504030201 {
		t.Errorf("Int64: wrong value: %x", stream.Int64())
	}
	if !stream.Complete() {
		t.Errorf("Int64: stream not complete")
	}
}

func TestDecodeInt64Negative(t *testing.T) {
	// Test negative value (0xFFFFFFFFFFFFFFFF = -1 in two's complement)
	stream := Decode(hx2b("FFFFFFFFFFFFFFFF"))
	if stream.Int64() != -1 {
		t.Errorf("Int64: wrong value: expected -1, got %d", stream.Int64())
	}
	if !stream.Complete() {
		t.Errorf("Int64: stream not complete")
	}
}

func TestDecodeTag4CC(t *testing.T) {
	stream := Decode(hx2b("41424344")) // "ABCD" in big-endian
	if stream.Tag4CC() != 0x41424344 {
		t.Errorf("Tag4CC: wrong value: %x", stream.Tag4CC())
	}
	if !stream.Complete() {
		t.Errorf("Tag4CC: stream not complete")
	}
}

func TestDecodeVarString(t *testing.T) {
	// Test VarString with "hello" (length 5 + "hello")
	stream := Decode(hx2b("0568656C6C6F"))
	if stream.VarString() != "hello" {
		t.Errorf("VarString: wrong value: expected 'hello', got '%s'", stream.VarString())
	}
	if !stream.Complete() {
		t.Errorf("VarString: stream not complete")
	}
}

func TestDecodeVarStringEmpty(t *testing.T) {
	// Test VarString with empty string
	stream := Decode(hx2b("00"))
	if stream.VarString() != "" {
		t.Errorf("VarString: wrong value: expected empty string, got '%s'", stream.VarString())
	}
	if !stream.Complete() {
		t.Errorf("VarString: stream not complete")
	}
}

func TestDecodePadString(t *testing.T) {
	// Test PadString with "hello" padded to 8 bytes with nulls
	stream := Decode(hx2b("68656C6C6F000000")) // "hello\0\0\0"
	if stream.PadString(8) != "hello" {
		t.Errorf("PadString: wrong value: expected 'hello', got '%s'", stream.PadString(8))
	}
	if !stream.Complete() {
		t.Errorf("PadString: stream not complete")
	}
}

func TestDecodePadStringNoPadding(t *testing.T) {
	// Test PadString with no padding
	stream := Decode(hx2b("68656C6C6F")) // "hello"
	if stream.PadString(5) != "hello" {
		t.Errorf("PadString: wrong value: expected 'hello', got '%s'", stream.PadString(5))
	}
	if !stream.Complete() {
		t.Errorf("PadString: stream not complete")
	}
}

func TestDecodePadStringEmpty(t *testing.T) {
	// Test PadString with empty string (all nulls)
	stream := Decode(hx2b("00000000")) // all nulls
	result := stream.PadString(4)
	if result != "" {
		t.Errorf("PadString: wrong value: expected empty string, got '%s' (len=%d, bytes=%x)", result, len(result), []byte(result))
	}
	if !stream.Complete() {
		t.Errorf("PadString: stream not complete")
	}
}

func TestDecodeRest(t *testing.T) {
	stream := Decode(hx2b("0102030405"))
	// Read first 2 bytes
	stream.Bytes(2)
	// Read rest
	rest := stream.Rest()
	if !bytes.Equal(rest, hx2b("030405")) {
		t.Errorf("Rest: wrong value: %x", rest)
	}
	if !stream.Complete() {
		t.Errorf("Rest: stream not complete")
	}
}

func TestDecodeRestEmpty(t *testing.T) {
	stream := Decode(hx2b("0102030405"))
	// Read all bytes first
	stream.Bytes(5)
	// Read rest (should be empty)
	rest := stream.Rest()
	if len(rest) != 0 {
		t.Errorf("Rest: expected empty, got %x", rest)
	}
	if !stream.Complete() {
		t.Errorf("Rest: stream not complete")
	}
}

func TestDecodeHas(t *testing.T) {
	stream := Decode(hx2b("0102030405"))
	if !stream.Has(5) {
		t.Errorf("Has: should have 5 bytes")
	}
	if !stream.Has(3) {
		t.Errorf("Has: should have 3 bytes")
	}
	if stream.Has(6) {
		t.Errorf("Has: should not have 6 bytes")
	}
}

func TestDecodeError(t *testing.T) {
	stream := Decode(hx2b("0102030405"))
	// Read some bytes but not all
	stream.Bytes(3)

	type TestStruct struct{}
	var testStruct TestStruct
	err := stream.Error(testStruct)
	if err == nil {
		t.Errorf("Error: should return error for incomplete stream")
	}
	if err.Error() != "wrong encoded size for: TestStruct (need 3 found 5)" {
		t.Errorf("Error: wrong error message: %s", err.Error())
	}
}

func TestDecodeErrorComplete(t *testing.T) {
	stream := Decode(hx2b("0102030405"))
	// Read all bytes
	stream.Bytes(5)

	type TestStruct struct{}
	var testStruct TestStruct
	err := stream.Error(testStruct)
	if err != nil {
		t.Errorf("Error: should not return error for complete stream: %s", err.Error())
	}
}

func TestDecodeErrorPointer(t *testing.T) {
	stream := Decode(hx2b("0102030405"))
	// Read some bytes but not all
	stream.Bytes(3)

	type TestStruct struct{}
	var testStruct *TestStruct
	err := stream.Error(testStruct)
	if err == nil {
		t.Errorf("Error: should return error for incomplete stream")
	}
	if err.Error() != "wrong encoded size for: TestStruct (need 3 found 5)" {
		t.Errorf("Error: wrong error message: %s", err.Error())
	}
}

// Overrun tests for missing methods
func TestDecodeOverrunBool(t *testing.T) {
	stream := Decode([]byte{})
	if stream.Bool() {
		t.Errorf("Bool: should return false for overrun")
	}
	if stream.Valid() {
		t.Errorf("Bool: stream should not be valid for overrun")
	}
	if stream.Complete() {
		t.Errorf("Bool: stream should not be complete for overrun")
	}
}

func TestDecodeOverrunUInt8(t *testing.T) {
	stream := Decode([]byte{})
	if stream.UInt8() != 0 {
		t.Errorf("UInt8: should return 0 for overrun")
	}
	if stream.Valid() {
		t.Errorf("UInt8: stream should not be valid for overrun")
	}
	if stream.Complete() {
		t.Errorf("UInt8: stream should not be complete for overrun")
	}
}

func TestDecodeOverrunInt64(t *testing.T) {
	stream := Decode(hx2b("01020304050607"))
	if stream.Int64() != 0 {
		t.Errorf("Int64: should return 0 for overrun")
	}
	if stream.Valid() {
		t.Errorf("Int64: stream should not be valid for overrun")
	}
	if stream.Complete() {
		t.Errorf("Int64: stream should not be complete for overrun")
	}
}

func TestDecodeOverrunTag4CC(t *testing.T) {
	stream := Decode(hx2b("010203"))
	if stream.Tag4CC() != 0 {
		t.Errorf("Tag4CC: should return 0 for overrun")
	}
	if stream.Valid() {
		t.Errorf("Tag4CC: stream should not be valid for overrun")
	}
	if stream.Complete() {
		t.Errorf("Tag4CC: stream should not be complete for overrun")
	}
}

func TestDecodeOverrunVarString(t *testing.T) {
	stream := Decode([]byte{})
	if stream.VarString() != "" {
		t.Errorf("VarString: should return empty string for overrun")
	}
	if stream.Valid() {
		t.Errorf("VarString: stream should not be valid for overrun")
	}
	if stream.Complete() {
		t.Errorf("VarString: stream should not be complete for overrun")
	}
}

func TestDecodeOverrunPadString(t *testing.T) {
	stream := Decode(hx2b("0102"))
	if stream.PadString(5) != "" {
		t.Errorf("PadString: should return empty string for overrun")
	}
	if stream.Valid() {
		t.Errorf("PadString: stream should not be valid for overrun")
	}
	if stream.Complete() {
		t.Errorf("PadString: stream should not be complete for overrun")
	}
}
