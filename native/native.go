// Package native determines host machine endianness
package native

import (
	"encoding/binary"
	"unsafe"
)

var Endian binary.ByteOrder

func init() {
	// https://stackoverflow.com/questions/51332658/any-better-way-to-check-endianness-in-go
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		Endian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		Endian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}
