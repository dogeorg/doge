package doge

import (
	"bytes"
	"testing"
)

func TestEncodeBytes(t *testing.T) {
	encoder := Encode(10)
	encoder.Bytes(hx2b("01020304"))
	result := encoder.Result()
	expected := hx2b("01020304")
	if !bytes.Equal(result, expected) {
		t.Errorf("Bytes: wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeBool(t *testing.T) {
	encoder := Encode(1)
	encoder.Bool(true)
	result := encoder.Result()
	expected := hx2b("01")
	if !bytes.Equal(result, expected) {
		t.Errorf("Bool(true): wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeBoolFalse(t *testing.T) {
	encoder := Encode(1)
	encoder.Bool(false)
	result := encoder.Result()
	expected := hx2b("00")
	if !bytes.Equal(result, expected) {
		t.Errorf("Bool(false): wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeUInt8(t *testing.T) {
	encoder := Encode(1)
	encoder.UInt8(0x42)
	result := encoder.Result()
	expected := hx2b("42")
	if !bytes.Equal(result, expected) {
		t.Errorf("UInt8: wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeUInt16(t *testing.T) {
	encoder := Encode(2)
	encoder.UInt16(0x0201)
	result := encoder.Result()
	expected := hx2b("0102")
	if !bytes.Equal(result, expected) {
		t.Errorf("UInt16: wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeUInt32(t *testing.T) {
	encoder := Encode(4)
	encoder.UInt32(0x04030201)
	result := encoder.Result()
	expected := hx2b("01020304")
	if !bytes.Equal(result, expected) {
		t.Errorf("UInt32: wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeUInt64(t *testing.T) {
	encoder := Encode(8)
	encoder.UInt64(0x0807060504030201)
	result := encoder.Result()
	expected := hx2b("0102030405060708")
	if !bytes.Equal(result, expected) {
		t.Errorf("UInt64: wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeInt64(t *testing.T) {
	encoder := Encode(8)
	encoder.Int64(0x0807060504030201)
	result := encoder.Result()
	expected := hx2b("0102030405060708")
	if !bytes.Equal(result, expected) {
		t.Errorf("Int64: wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeInt64Negative(t *testing.T) {
	encoder := Encode(8)
	encoder.Int64(-1)
	result := encoder.Result()
	expected := hx2b("FFFFFFFFFFFFFFFF")
	if !bytes.Equal(result, expected) {
		t.Errorf("Int64(-1): wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeTag4CC(t *testing.T) {
	encoder := Encode(4)
	encoder.Tag4CC(0x41424344) // "ABCD"
	result := encoder.Result()
	expected := hx2b("41424344")
	if !bytes.Equal(result, expected) {
		t.Errorf("Tag4CC: wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeVarUIntSingleByte(t *testing.T) {
	encoder := Encode(1)
	encoder.VarUInt(0x42)
	result := encoder.Result()
	expected := hx2b("42")
	if !bytes.Equal(result, expected) {
		t.Errorf("VarUInt(0x42): wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeVarUIntTwoBytes(t *testing.T) {
	encoder := Encode(3)
	encoder.VarUInt(0x0201)
	result := encoder.Result()
	expected := hx2b("FD0102")
	if !bytes.Equal(result, expected) {
		t.Errorf("VarUInt(0x0201): wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeVarUIntFourBytes(t *testing.T) {
	encoder := Encode(5)
	encoder.VarUInt(0x04030201)
	result := encoder.Result()
	expected := hx2b("FE01020304")
	if !bytes.Equal(result, expected) {
		t.Errorf("VarUInt(0x04030201): wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeVarUIntEightBytes(t *testing.T) {
	encoder := Encode(9)
	encoder.VarUInt(0x0807060504030201)
	result := encoder.Result()
	expected := hx2b("FF0102030405060708")
	if !bytes.Equal(result, expected) {
		t.Errorf("VarUInt(0x0807060504030201): wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeVarUIntBoundaryValues(t *testing.T) {
	// Test boundary values
	testCases := []struct {
		value    uint64
		expected []byte
	}{
		{0xFC, hx2b("FC")},                        // Single byte max
		{0xFD, hx2b("FDFD00")},                    // Two byte min
		{0xFFFF, hx2b("FDFFFF")},                  // Two byte max
		{0x10000, hx2b("FE00000100")},             // Four byte min
		{0xFFFFFFFF, hx2b("FEFFFFFFFF")},          // Four byte max
		{0x100000000, hx2b("FF0000000001000000")}, // Eight byte min
	}

	for _, tc := range testCases {
		encoder := Encode(10)
		encoder.VarUInt(tc.value)
		result := encoder.Result()
		if !bytes.Equal(result, tc.expected) {
			t.Errorf("VarUInt(%d): wrong value: expected %x, got %x", tc.value, tc.expected, result)
		}
	}
}

func TestEncodeVarString(t *testing.T) {
	encoder := Encode(10)
	encoder.VarString("hello")
	result := encoder.Result()
	expected := hx2b("0568656C6C6F")
	if !bytes.Equal(result, expected) {
		t.Errorf("VarString('hello'): wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeVarStringEmpty(t *testing.T) {
	encoder := Encode(1)
	encoder.VarString("")
	result := encoder.Result()
	expected := hx2b("00")
	if !bytes.Equal(result, expected) {
		t.Errorf("VarString(''): wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodePadString(t *testing.T) {
	encoder := Encode(8)
	fit := encoder.PadString(8, "hello")
	result := encoder.Result()
	expected := hx2b("68656C6C6F000000")
	if !bytes.Equal(result, expected) {
		t.Errorf("PadString(8, 'hello'): wrong value: expected %x, got %x", expected, result)
	}
	if !fit {
		t.Errorf("PadString(8, 'hello'): should fit, got truncated")
	}
}

func TestEncodePadStringExactFit(t *testing.T) {
	encoder := Encode(5)
	fit := encoder.PadString(5, "hello")
	result := encoder.Result()
	expected := hx2b("68656C6C6F")
	if !bytes.Equal(result, expected) {
		t.Errorf("PadString(5, 'hello'): wrong value: expected %x, got %x", expected, result)
	}
	if !fit {
		t.Errorf("PadString(5, 'hello'): should fit, got truncated")
	}
}

func TestEncodePadStringTruncated(t *testing.T) {
	encoder := Encode(3)
	fit := encoder.PadString(3, "hello")
	result := encoder.Result()
	expected := hx2b("68656C")
	if !bytes.Equal(result, expected) {
		t.Errorf("PadString(3, 'hello'): wrong value: expected %x, got %x", expected, result)
	}
	if fit {
		t.Errorf("PadString(3, 'hello'): should be truncated, got fit")
	}
}

func TestEncodePadStringEmpty(t *testing.T) {
	encoder := Encode(4)
	fit := encoder.PadString(4, "")
	result := encoder.Result()
	expected := hx2b("00000000")
	if !bytes.Equal(result, expected) {
		t.Errorf("PadString(4, ''): wrong value: expected %x, got %x", expected, result)
	}
	if !fit {
		t.Errorf("PadString(4, ''): should fit, got truncated")
	}
}

func TestEncodeResult(t *testing.T) {
	encoder := Encode(5)
	encoder.Bytes(hx2b("01020304"))
	result := encoder.Result()
	expected := hx2b("01020304")
	if !bytes.Equal(result, expected) {
		t.Errorf("Result: wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeMultipleOperations(t *testing.T) {
	encoder := Encode(20)
	encoder.Bool(true)
	encoder.UInt8(0x42)
	encoder.UInt16(0x0201)
	encoder.UInt32(0x04030201)
	encoder.VarString("test")

	result := encoder.Result()
	expected := hx2b("01420102010203040474657374")
	if !bytes.Equal(result, expected) {
		t.Errorf("Multiple operations: wrong value: expected %x, got %x", expected, result)
	}
}

func TestEncodeEmpty(t *testing.T) {
	encoder := Encode(0)
	result := encoder.Result()
	if len(result) != 0 {
		t.Errorf("Empty encoder: expected empty result, got %x", result)
	}
}

func TestEncodeGrowth(t *testing.T) {
	// Test that encoder grows beyond initial capacity
	encoder := Encode(2) // Start with small capacity
	encoder.Bytes(hx2b("0102030405060708"))
	result := encoder.Result()
	expected := hx2b("0102030405060708")
	if !bytes.Equal(result, expected) {
		t.Errorf("Growth: wrong value: expected %x, got %x", expected, result)
	}
}
