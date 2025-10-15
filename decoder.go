package doge

import (
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
)

// Decoder is a helper for decoding data from a byte slice.
// All numbers are assumed to be encoded little-endian.
type Decoder struct {
	buf []byte // buffer to decode
	pos int    // current (unread) byte position
	len int    // length of the buffer
}

// Decode creates a new Decoder from a byte slice.
func Decode(b []byte) *Decoder {
	return &Decoder{buf: b, len: len(b)}
}

// Valid returns true if all reads have succeeded without reading past the end of the data.
func (d *Decoder) Valid() bool {
	return d.pos <= d.len
}

// Complete returns true if all the data has been read; implies Valid()
func (d *Decoder) Complete() bool {
	return d.pos == d.len
}

// Error returns nil if Complete(), or an error describing the wrong encoded size.
// `to` should be the struct (or interface) being parsed into, for error reporting.
func (d *Decoder) Error(to any) error {
	if d.Complete() {
		return nil
	}
	into := reflect.TypeOf(to)
	if into.Kind() == reflect.Ptr {
		into = into.Elem()
	}
	return fmt.Errorf("wrong encoded size for: %v (need %v found %v)", into.Name(), d.pos, d.len)
}

// Has checks if there are at least n bytes remaining in the buffer.
func (d *Decoder) Has(n int) bool {
	return d.pos+n <= d.len
}

// Bytes reads n bytes from the buffer and advances the position.
func (d *Decoder) Bytes(num int) []byte {
	pos := d.pos
	d.pos += num
	if pos+num <= d.len {
		return d.buf[pos : pos+num]
	}
	return nil
}

// Rest reads all remaining bytes in the buffer.
func (d *Decoder) Rest() []byte {
	p := d.pos
	d.pos = d.len
	return d.buf[p:]
}

// Bool reads a boolean (byte) value from the buffer.
func (d *Decoder) Bool() bool {
	pos := d.pos
	d.pos += 1
	if pos+1 <= d.len {
		return d.buf[pos] != 0
	}
	return false
}

// UInt8 reads an unsigned 8-bit integer from the buffer.
func (d *Decoder) UInt8() uint8 {
	pos := d.pos
	d.pos += 1
	if pos+1 <= d.len {
		return d.buf[pos]
	}
	return 0
}

// UInt16le reads an unsigned 16-bit integer from the buffer in little-endian order.
func (d *Decoder) UInt16() uint16 {
	pos := d.pos
	d.pos += 2
	if pos+2 <= d.len {
		return binary.LittleEndian.Uint16(d.buf[pos : pos+2])
	}
	return 0
}

// UInt32le reads an unsigned 32-bit integer from the buffer in little-endian order.
func (d *Decoder) UInt32() uint32 {
	pos := d.pos
	d.pos += 4
	if pos+4 <= d.len {
		return binary.LittleEndian.Uint32(d.buf[pos : pos+4])
	}
	return 0
}

// UInt64le reads an unsigned 64-bit integer from the buffer in little-endian order.
func (d *Decoder) UInt64() uint64 {
	pos := d.pos
	d.pos += 8
	if pos+8 <= d.len {
		return binary.LittleEndian.Uint64(d.buf[pos : pos+8])
	}
	return 0
}

// Int64le reads a signed 64-bit integer from the buffer in little-endian order.
func (d *Decoder) Int64() int64 {
	pos := d.pos
	d.pos += 8
	if pos+8 <= d.len {
		return int64(binary.LittleEndian.Uint64(d.buf[pos : pos+8]))
	}
	return 0
}

// Tag4CC reads a 4-byte Tag.
func (d *Decoder) Tag4CC() Tag4CC {
	pos := d.pos
	d.pos += 4
	if pos+4 <= d.len {
		// uses BigEndian to preserve the order of the 4 characters.
		return Tag4CC(binary.BigEndian.Uint32(d.buf[pos : pos+4]))
	}
	return 0
}

// VarUInt reads a variable-length unsigned integer from the buffer.
func (d *Decoder) VarUInt() uint64 {
	pos := d.pos
	d.pos += 1
	if pos+1 <= d.len {
		val := d.buf[pos]
		if val < 253 {
			return uint64(val)
		}
		if val == 253 {
			return uint64(d.UInt16())
		}
		if val == 254 {
			return uint64(d.UInt32())
		}
		return d.UInt64()
	}
	return 0
}

// VarString reads a variable-length string from the buffer.
func (d *Decoder) VarString() string {
	len := d.VarUInt()
	if len > math.MaxInt {
		panic(fmt.Sprintf("decoded string length too long (greater than max-int): %v", len))
	}
	data := d.Bytes(int(len))
	return string(data)
}

// PadString reads a fixed-length padded string from the buffer, trimming trailing null bytes.
func (d *Decoder) PadString(size int) string {
	data := d.Bytes(size)
	if data == nil || size <= 0 {
		return ""
	}
	end := size - 1
	for end >= 0 && data[end] == 0 {
		end--
	}
	if end < 0 {
		return ""
	}
	return string(data[:end+1])
}
