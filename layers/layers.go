// Package layers
package layers

import (
	"fmt"
	"unsafe"
)

const maxLenSummary = 110

var LayerMap = map[string]Layer{
	"ETH":    &EthernetFrame{},
	"IPv4":   &IPv4Packet{},
	"IPv6":   &IPv6Packet{},
	"ARP":    &ARPPacket{},
	"TCP":    &TCPSegment{},
	"UDP":    &UDPSegment{},
	"ICMP":   &ICMPSegment{},
	"ICMPv6": &ICMPv6Segment{},
	"DNS":    &DNSMessage{},
	"FTP":    &FTPMessage{},
	"HTTP":   &HTTPMessage{},
	"SNMP":   &SNMPMessage{},
	"SSH":    &SSHMessage{},
	"TLS":    &TLSMessage{},
}

var (
	bspace            = []byte(" ")
	dash              = []byte("- ")
	lfd               = []byte("\n- ")
	slfd              = "\n- "
	lf                = []byte("\n")
	crlf              = []byte("\r\n")
	dcrlf             = []byte("\r\n\r\n")
	ellipsis          = []byte("...")
	contdata          = []byte("Continuation data")
	ErrParsingAddress = fmt.Errorf("failed parsing IP address")
	ErrSliceBounds    = fmt.Errorf("slice bounds out of range")
)

type Layer interface {
	fmt.Stringer
	Parse(data []byte) error
	NextLayer() (layer string, payload []byte)
	Summary() string
}

func GetNextLayer(layer string) Layer {
	switch layer {
	case "ETH":
		return &EthernetFrame{}
	case "IPv4":
		return &IPv4Packet{}
	case "IPv6":
		return &IPv6Packet{}
	case "ARP":
		return &ARPPacket{}
	case "TCP":
		return &TCPSegment{}
	case "UDP":
		return &UDPSegment{}
	case "ICMP":
		return &ICMPSegment{}
	case "ICMPv6":
		return &ICMPv6Segment{}
	case "DNS":
		return &DNSMessage{}
	case "FTP":
		return &FTPMessage{}
	case "HTTP":
		return &HTTPMessage{}
	case "SNMP":
		return &SNMPMessage{}
	case "SSH":
		return &SSHMessage{}
	case "TLS":
		return &TLSMessage{}
	default:
		return nil
	}
}

func bytesToStr(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func joinBytes(bs ...[]byte) []byte {
	n := 0
	for _, v := range bs {
		n += len(v)
	}
	b, i := make([]byte, n), 0
	for _, v := range bs {
		i += copy(b[i:], v)
	}
	return b
}

func add16WithCarryWrapAround(x, y uint16) uint16 {
	sum32 := uint32(x) + uint32(y)
	sum32 = (sum32 & 0xFFFF) + (sum32 >> 16)
	return uint16(sum32)
}
