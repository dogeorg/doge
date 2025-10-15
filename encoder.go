package doge

import (
	"encoding/binary"
)

// Encoder is a helper for encoding data to a byte slice.
// All numbers are encoded little-endian.
type Encoder struct {
	buf []byte
}

// Encode creates a new Encoder for a given size.
// The underlying buffer will grow as necessary.
func Encode(size_hint int) *Encoder {
	return &Encoder{buf: make([]byte, 0, size_hint)}
}

// Get the encoded array of bytes
func (e *Encoder) Result() []byte {
	return e.buf
}

// Encode a slice of bytes.
// No length is encoded: use VarUInt to prefix with a (non-fixed) length.
func (e *Encoder) Bytes(b []byte) {
	e.buf = append(e.buf, b...)
}

// Encode a boolean as a byte.
func (e *Encoder) Bool(b bool) {
	var v byte = 0
	if b {
		v = 1
	}
	e.buf = append(e.buf, v)
}

// Encode an unsigned byte as itself.
func (e *Encoder) UInt8(v uint8) {
	e.buf = append(e.buf, v)
}

// Encode an unsigned 16-bit number in little-endian order.
func (e *Encoder) UInt16(v uint16) {
	e.buf = binary.LittleEndian.AppendUint16(e.buf, v)
}

// Encode an unsigned 32-bit number in little-endian order.
func (e *Encoder) UInt32(v uint32) {
	e.buf = binary.LittleEndian.AppendUint32(e.buf, v)
}

// Encode an unsigned 64-bit number in little-endian order.
func (e *Encoder) UInt64(v uint64) {
	e.buf = binary.LittleEndian.AppendUint64(e.buf, v)
}

// Encode a signed 64-bit number in little-endian order.
func (e *Encoder) Int64(v int64) {
	e.buf = binary.LittleEndian.AppendUint64(e.buf, uint64(v))
}

// Tag4CC encodes a Four Character Code TAG in big-endian order,
// to preserve the order of the ASCII characters in the stream.
func (e *Encoder) Tag4CC(v Tag4CC) {
	// uses BigEndian to preserve the order of the 4 characters.
	e.buf = binary.BigEndian.AppendUint32(e.buf, uint32(v))
}

// Encode an unsigned integer of varying length:
// A single byte up to 0xFC (252)
// 0xFD + encoded 16-bit number, up to 0xFFFF (65536)
// 0xFE + encoded 32-bit number, up to 0xFFFFFFFF (4294967295)
// 0xFF + encoded 64-bit number, up to 0xFFFFFFFFFFFFFFFF (18446744073709551615)
// This encoding was borrowed from Bitcoin.
func (e *Encoder) VarUInt(val uint64) {
	if val < 0xFD {
		e.buf = append(e.buf, byte(val))
	} else if val <= 0xFFFF {
		e.buf = append(e.buf, 0xFD)
		e.buf = binary.LittleEndian.AppendUint16(e.buf, uint16(val))
	} else if val <= 0xFFFFFFFF {
		e.buf = append(e.buf, 0xFE)
		e.buf = binary.LittleEndian.AppendUint32(e.buf, uint32(val))
	} else {
		e.buf = append(e.buf, 0xFF)
		e.buf = binary.LittleEndian.AppendUint64(e.buf, val)
	}
}

// Encodes a VarUInt length, followed by the string bytes.
func (e *Encoder) VarString(v string) {
	b := []byte(v)
	e.VarUInt(uint64(len(b)))
	e.buf = append(e.buf, b...)
}

// Encodes a string padded to a fixed-size field with zero bytes.
// If the string is too long to fit, it is truncated.
// Returns true if the string fits, false if it was truncated.
func (e *Encoder) PadString(size uint64, v string) bool {
	bytes := []byte(v)
	used := uint64(len(v))

	// Add the string bytes (truncated if necessary)
	if used > size {
		e.buf = append(e.buf, bytes[0:size]...)
		return false // truncated
	} else {
		e.buf = append(e.buf, bytes...)

		// Add padding zeros
		for used < size {
			e.buf = append(e.buf, 0)
			used++
		}
		return true // fits within the size
	}
}
