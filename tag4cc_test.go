package doge

import (
	"bytes"
	"testing"
)

func TestTag4CCString(t *testing.T) {
	tag := Tag4CC(0x41424344) // "ABCD"
	result := tag.String()
	expected := "ABCD"
	if result != expected {
		t.Errorf("Tag4CC.String(): expected '%s', got '%s'", expected, result)
	}
}

func TestTag4CCStringEmpty(t *testing.T) {
	tag := Tag4CC(0x00000000) // All zeros
	result := tag.String()
	expected := "\x00\x00\x00\x00"
	if result != expected {
		t.Errorf("Tag4CC.String(): expected '%s', got '%s'", expected, result)
	}
}

func TestTag4CCStringMax(t *testing.T) {
	tag := Tag4CC(0xFFFFFFFF) // All ones
	result := tag.String()
	expected := "\xFF\xFF\xFF\xFF"
	if result != expected {
		t.Errorf("Tag4CC.String(): expected '%s', got '%s'", expected, result)
	}
}

func TestTag4CCStringMixed(t *testing.T) {
	tag := Tag4CC(0x54657374) // "Test"
	result := tag.String()
	expected := "Test"
	if result != expected {
		t.Errorf("Tag4CC.String(): expected '%s', got '%s'", expected, result)
	}
}

func TestTag4CCBytes(t *testing.T) {
	tag := Tag4CC(0x41424344) // "ABCD"
	result := tag.Bytes()
	expected := []byte{0x41, 0x42, 0x43, 0x44}
	if !bytes.Equal(result, expected) {
		t.Errorf("Tag4CC.Bytes(): expected %x, got %x", expected, result)
	}
}

func TestTag4CCBytesEmpty(t *testing.T) {
	tag := Tag4CC(0x00000000) // All zeros
	result := tag.Bytes()
	expected := []byte{0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(result, expected) {
		t.Errorf("Tag4CC.Bytes(): expected %x, got %x", expected, result)
	}
}

func TestTag4CCBytesMax(t *testing.T) {
	tag := Tag4CC(0xFFFFFFFF) // All ones
	result := tag.Bytes()
	expected := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	if !bytes.Equal(result, expected) {
		t.Errorf("Tag4CC.Bytes(): expected %x, got %x", expected, result)
	}
}

func TestTag4CCBytesMixed(t *testing.T) {
	tag := Tag4CC(0x54657374) // "Test"
	result := tag.Bytes()
	expected := []byte{0x54, 0x65, 0x73, 0x74}
	if !bytes.Equal(result, expected) {
		t.Errorf("Tag4CC.Bytes(): expected %x, got %x", expected, result)
	}
}

func TestNewTag(t *testing.T) {
	tag := NewTag("ABCD")
	expected := Tag4CC(0x41424344)
	if tag != expected {
		t.Errorf("NewTag('ABCD'): expected 0x%08X, got 0x%08X", expected, tag)
	}
}

func TestNewTagNumbers(t *testing.T) {
	tag := NewTag("1234")
	expected := Tag4CC(0x31323334) // ASCII values for '1', '2', '3', '4'
	if tag != expected {
		t.Errorf("NewTag('1234'): expected 0x%08X, got 0x%08X", expected, tag)
	}
}

func TestNewTagSpecialChars(t *testing.T) {
	tag := NewTag("!@#$")
	expected := Tag4CC(0x21402324) // ASCII values for '!', '@', '#', '$'
	if tag != expected {
		t.Errorf("NewTag('!@#$'): expected 0x%08X, got 0x%08X", expected, tag)
	}
}

func TestNewTagEmpty(t *testing.T) {
	tag := NewTag("\x00\x00\x00\x00")
	expected := Tag4CC(0x00000000)
	if tag != expected {
		t.Errorf("NewTag('\\x00\\x00\\x00\\x00'): expected 0x%08X, got 0x%08X", expected, tag)
	}
}

func TestNewTagMax(t *testing.T) {
	tag := NewTag("\xFF\xFF\xFF\xFF")
	expected := Tag4CC(0xFFFFFFFF)
	if tag != expected {
		t.Errorf("NewTag('\\xFF\\xFF\\xFF\\xFF'): expected 0x%08X, got 0x%08X", expected, tag)
	}
}

func TestNewTagTooShort(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NewTag('ABC'): should panic for string too short")
		}
	}()
	NewTag("ABC")
}

func TestNewTagTooLong(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NewTag('ABCDE'): should panic for string too long")
		}
	}()
	NewTag("ABCDE")
}

func TestNewTagEmptyString(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NewTag(''): should panic for empty string")
		}
	}()
	NewTag("")
}

func TestTag4CCRoundTrip(t *testing.T) {
	// Test that NewTag and String are inverse operations
	original := "ABCD"
	tag := NewTag(original)
	result := tag.String()
	if result != original {
		t.Errorf("Round trip: expected '%s', got '%s'", original, result)
	}
}

func TestTag4CCRoundTripBytes(t *testing.T) {
	// Test that NewTag and Bytes are consistent
	original := []byte{0x41, 0x42, 0x43, 0x44}
	tag := NewTag(string(original))
	result := tag.Bytes()
	if !bytes.Equal(result, original) {
		t.Errorf("Round trip bytes: expected %x, got %x", original, result)
	}
}

func TestTag4CCStringBytesConsistency(t *testing.T) {
	// Test that String() and Bytes() return consistent data
	tag := Tag4CC(0x41424344)
	stringResult := tag.String()
	bytesResult := tag.Bytes()

	// Convert string to bytes for comparison
	stringBytes := []byte(stringResult)
	if !bytes.Equal(stringBytes, bytesResult) {
		t.Errorf("String/Bytes consistency: String()=%x, Bytes()=%x", stringBytes, bytesResult)
	}
}

func TestTag4CCZero(t *testing.T) {
	tag := Tag4CC(0)
	if tag.String() != "\x00\x00\x00\x00" {
		t.Errorf("Zero tag: expected null bytes, got '%s'", tag.String())
	}
	if !bytes.Equal(tag.Bytes(), []byte{0, 0, 0, 0}) {
		t.Errorf("Zero tag bytes: expected [0,0,0,0], got %x", tag.Bytes())
	}
}

func TestTag4CCMax(t *testing.T) {
	tag := Tag4CC(0xFFFFFFFF)
	if tag.String() != "\xFF\xFF\xFF\xFF" {
		t.Errorf("Max tag: expected all 0xFF, got '%s'", tag.String())
	}
	if !bytes.Equal(tag.Bytes(), []byte{0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Errorf("Max tag bytes: expected all 0xFF, got %x", tag.Bytes())
	}
}
