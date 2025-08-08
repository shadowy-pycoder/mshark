// Package layers
package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"
)

const maxLenSummary = 110

var Layers = []string{
	"ETH",
	"IPv4",
	"IPv6",
	"ARP",
	"TCP",
	"UDP",
	"ICMP",
	"ICMPv6",
	"DNS",
	"FTP",
	"HTTP",
	"SNMP",
	"SSH",
	"TLS",
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
	NextLayer() Layer
	Summary() string
	Name() string
}

func parseNextLayerFallback(data []byte) Layer {
	if len(data) == 0 {
		return nil
	}
	for _, layer := range Layers {
		next := GetNextLayer(layer)
		if err := next.Parse(data); err == nil {
			return next
		}
	}
	return nil
}

func parseNextLayerFromBytes(data []byte) Layer {
	if len(data) == 0 {
		return nil
	}
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	var next Layer
	firstByte := buf[0]
	if firstByte >= 0x45 && firstByte <= 0x4F {
		next = GetNextLayer("IPv4")
		if err := next.Parse(buf); err == nil {
			return next
		}
	}
	if firstByte>>4 == 6 {
		next = GetNextLayer("IPv6")
		if err := next.Parse(buf); err == nil {
			return next
		}
	}
	if firstByte == HandshakeTLSVal {
		next = GetNextLayer("TLS")
		if err := next.Parse(buf); err == nil {
			return next
		}
	}
	if firstByte == 0x30 {
		next = GetNextLayer("SNMP")
		if err := next.Parse(buf); err == nil {
			return next
		}
	}
	if len(buf) > 3 {
		b1 := binary.BigEndian.Uint16(buf[0:2])
		b2 := binary.BigEndian.Uint16(buf[2:4])
		if b1 == 1 && (b2 == 0x0800 || b2 == 0x86dd) {
			next = GetNextLayer("ARP")
			if err := next.Parse(buf); err == nil {
				return next
			}
		}
	}
	if len(buf) > 15 {
		b1 := binary.BigEndian.Uint16(buf[12:14])
		if b1 == 0x0806 || b1 == 0x0800 || b1 == 0x86dd {
			next = GetNextLayer("ETH")
			if err := next.Parse(buf); err == nil {
				return next
			}
		}
	}
	if bytes.Contains(buf, protohttp10) || bytes.Contains(buf, protohttp11) {
		next = GetNextLayer("HTTP")
		if err := next.Parse(buf); err == nil {
			return next
		}
	}
	if bytes.Contains(buf, protoSSH) {
		next = GetNextLayer("SSH")
		if err := next.Parse(buf); err == nil {
			return next
		}
	}
	return nil
}

func addrMatch(src, dst *uint16, ports []uint16) bool {
	var srcPort, dstPort uint16
	if src != nil {
		srcPort = *src
	}
	if dst != nil {
		dstPort = *dst
	}
	for _, port := range ports {
		if srcPort == port || dstPort == port {
			return true
		}
	}
	return false
}

func parseNextLayerFromPorts(data []byte, src, dst *uint16) Layer {
	if len(data) == 0 {
		return nil
	}
	var next Layer
	switch {
	case addrMatch(src, dst, []uint16{53, 5353, 853, 5355}):
		next = GetNextLayer("DNS")
	case addrMatch(src, dst, []uint16{80, 8080, 8000, 8888, 81, 591, 5911}):
		next = GetNextLayer("HTTP")
	case addrMatch(src, dst, []uint16{161, 162, 10161, 10162, 1161, 2161}):
		next = GetNextLayer("SNMP")
	case addrMatch(src, dst, []uint16{21, 20, 2121, 8021}):
		next = GetNextLayer("FTP")
	case addrMatch(src, dst, []uint16{22, 2222, 2200, 222, 2022}):
		next = GetNextLayer("SSH")
	case addrMatch(src, dst, []uint16{443, 465, 993, 995, 8443, 9443, 10443, 8444, 5228}):
		next = GetNextLayer("TLS")
	default:
		return nil
	}
	if err := next.Parse(data); err == nil {
		return next
	} else {
		return nil
	}
}

func ParseNextLayer(data []byte, src, dst *uint16) Layer {
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	var next Layer
	if src != nil || dst != nil {
		if next = parseNextLayerFromPorts(buf, src, dst); next != nil {
			return next
		}
	}
	if next = parseNextLayerFromBytes(buf); next != nil {
		return next
	}
	return parseNextLayerFallback(buf)
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
