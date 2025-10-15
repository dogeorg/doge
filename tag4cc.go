package doge

import (
	"encoding/binary"
	"fmt"
)

type Tag4CC uint32 // Big-Endian Four Character Code

func (t Tag4CC) String() string {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(t))
	return string(buf[:])
}

func (t Tag4CC) Bytes() []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(t))
	return buf[:]
}

func NewTag(tag string) Tag4CC {
	if len(tag) != 4 {
		panic(fmt.Sprintf("NewTag: Tag4CC must be 4 bytes, got '%v'", tag))
	}
	// BigEndian preserves the order of tag bytes in memory (more readable)
	return Tag4CC(binary.BigEndian.Uint32([]byte(tag)))
}
