// Package layers
package layers

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/shadowy-pycoder/mshark/native"
)

const maxLenSummary = 110

type LayerName string

const (
	LayerETH    LayerName = "ETH"
	LayerIPv4   LayerName = "IPv4"
	LayerIPv6   LayerName = "IPv6"
	LayerARP    LayerName = "ARP"
	LayerTCP    LayerName = "TCP"
	LayerUDP    LayerName = "UDP"
	LayerICMP   LayerName = "ICMP"
	LayerICMPv6 LayerName = "ICMPv6"
	LayerDNS    LayerName = "DNS"
	LayerFTP    LayerName = "FTP"
	LayerHTTP   LayerName = "HTTP"
	LayerSNMP   LayerName = "SNMP"
	LayerSSH    LayerName = "SSH"
	LayerTLS    LayerName = "TLS"
)

var Layers = []LayerName{
	LayerETH,
	LayerIPv4,
	LayerIPv6,
	LayerTLS,
	LayerHTTP,
	LayerDNS,
	LayerARP,
	LayerTCP,
	LayerUDP,
	LayerICMP,
	LayerICMPv6,
	LayerSNMP,
	LayerSSH,
	LayerFTP,
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
	Name() LayerName
}

func parseNextLayerFallback(data []byte) Layer {
	if len(data) == 0 {
		return nil
	}
	for _, layer := range Layers {
		next := GetLayer(layer)
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
		next = GetLayer(LayerIPv4)
		if err := next.Parse(buf); err == nil {
			return next
		}
	}
	if firstByte>>4 == 6 {
		next = GetLayer(LayerIPv6)
		if err := next.Parse(buf); err == nil {
			return next
		}
	}
	if firstByte == HandshakeTLSVal {
		next = GetLayer(LayerTLS)
		if err := next.Parse(buf); err == nil {
			return next
		}
	}
	if checkFTP(buf) {
		next = GetLayer(LayerFTP)
		if err := next.Parse(buf); err == nil {
			return next
		}
	}
	if len(buf) > 3 {
		b1 := binary.BigEndian.Uint16(buf[0:2])
		b2 := binary.BigEndian.Uint16(buf[2:4])
		if b1 == 1 && (b2 == 0x0800 || b2 == 0x86dd) {
			next = GetLayer(LayerARP)
			if err := next.Parse(buf); err == nil {
				return next
			}
		}
	}
	if checkSNMP(buf) {
		next = GetLayer(LayerSNMP)
		if err := next.Parse(buf); err == nil {
			return next
		}
	}
	if len(buf) > 15 {
		b1 := binary.BigEndian.Uint16(buf[12:14])
		if b1 == 0x0806 || b1 == 0x0800 || b1 == 0x86dd {
			next = GetLayer(LayerETH)
			if err := next.Parse(buf); err == nil {
				return next
			}
		}
	}
	if bytes.Contains(buf, protohttp10) || bytes.Contains(buf, protohttp11) {
		next = GetLayer(LayerHTTP)
		if err := next.Parse(buf); err == nil {
			return next
		}
	}
	if bytes.Contains(buf, protoSSH) {
		next = GetLayer(LayerSSH)
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
		next = GetLayer(LayerDNS)
	case addrMatch(src, dst, []uint16{80, 8080, 8000, 8888, 81, 591, 5911}):
		next = GetLayer(LayerHTTP)
	case addrMatch(src, dst, []uint16{161, 162, 10161, 10162, 1161, 2161}):
		next = GetLayer(LayerSNMP)
	case addrMatch(src, dst, []uint16{21, 20, 2121, 8021}):
		next = GetLayer(LayerFTP)
	case addrMatch(src, dst, []uint16{22, 2222, 2200, 222, 2022}):
		next = GetLayer(LayerSSH)
	case addrMatch(src, dst, []uint16{443, 465, 993, 995, 8443, 9443, 10443, 8444, 5228}):
		next = GetLayer(LayerTLS)
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
	return parseNextLayerFromBytes(buf)
}

func GetLayer(layer LayerName) Layer {
	switch layer {
	case LayerETH:
		return &EthernetFrame{}
	case LayerIPv4:
		return &IPv4Packet{}
	case LayerIPv6:
		return &IPv6Packet{}
	case LayerARP:
		return &ARPPacket{}
	case LayerTCP:
		return &TCPSegment{}
	case LayerUDP:
		return &UDPSegment{}
	case LayerICMP:
		return &ICMPSegment{}
	case LayerICMPv6:
		return &ICMPv6Segment{}
	case LayerDNS:
		return &DNSMessage{}
	case LayerFTP:
		return &FTPMessage{}
	case LayerHTTP:
		return &HTTPMessage{}
	case LayerSNMP:
		return &SNMPMessage{}
	case LayerSSH:
		return &SSHMessage{}
	case LayerTLS:
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

func CalculateInternetChecksum(data []byte, checksumOffset int) (uint16, error) {
	var sum uint16
	dataLength := len(data)
	for i := 0; i+1 < dataLength; i += 2 {
		if i != checksumOffset {
			sum = add16WithCarryWrapAround(sum, binary.BigEndian.Uint16(data[i:i+2]))
		}
	}
	if dataLength&1 == 1 {
		sum = add16WithCarryWrapAround(sum, uint16(data[dataLength-1])<<8)
	}
	sum = ^sum
	if sum == 0 {
		sum = 0xFFFF
	}
	return sum, nil
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isUpper(b byte) bool {
	return b >= 'A' && b <= 'Z'
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateRandomUint16LE() (uint16, error) {
	b, err := GenerateRandomBytes(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func GenerateRandomUint16BE() (uint16, error) {
	b, err := GenerateRandomBytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func GenerateRandomUint16NE() (uint16, error) {
	b, err := GenerateRandomBytes(2)
	if err != nil {
		return 0, err
	}
	return native.Endian.Uint16(b), nil
}

func MustGenerateRandomUint16NE() uint16 {
	rn, err := GenerateRandomUint16NE()
	if err != nil {
		panic(err)
	}
	return rn
}

func GenerateRandomUint32LE() (uint32, error) {
	b, err := GenerateRandomBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func MustGenerateRandomUint32LE() uint32 {
	rn, err := GenerateRandomUint32LE()
	if err != nil {
		panic(err)
	}
	return rn
}

func GenerateRandomUint32BE() (uint32, error) {
	b, err := GenerateRandomBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func MustGenerateRandomUint32BE() uint32 {
	rn, err := GenerateRandomUint32BE()
	if err != nil {
		panic(err)
	}
	return rn
}

func pad8(size int) int {
	return (8 - (size & 7)) & 7
}

func bTou8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
