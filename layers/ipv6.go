package layers

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const headerSizeIPv6 = 40

type TrafficClass struct {
	Raw      uint8
	DSCP     uint8
	DSCPDesc string
	ECN      uint8
}

func newTrafficiClass(tc uint8) *TrafficClass {
	dscpbin := tc >> 2
	return &TrafficClass{
		Raw:      tc,
		DSCP:     dscpbin,
		DSCPDesc: dscpdesc(dscpbin),
		ECN:      tc & 3,
	}
}

func (p *TrafficClass) String() string {
	return fmt.Sprintf("%#02x DSCP: %s (%#06b) ECN: %#02b", p.Raw, p.DSCPDesc, p.DSCP, p.ECN)
}

// An IPv6 packet is the smallest message entity exchanged using Internet Protocol version 6 (IPv6).
// IPv6 protocol defined in RFC 2460.
type IPv6Packet struct {
	Version        uint8         // 4 bits version field (for IPv6, this is always equal to 6).
	TrafficClass   *TrafficClass // 6 + 2 bits holds DS and ECN values.
	FlowLabel      uint32        // 20 bits high-entropy identifier of a flow of packets between a source and destination.
	PayloadLength  uint16        // 16 bits the size of the payload in octets, including any extension headers.
	NextHeader     uint8         // 8 bits specifies the type of the next header.
	NextHeaderDesc string        // next header description
	// 8 bits replaces the time to live field in IPv4. This value is decremented by one at each forwarding node
	// and the packet is discarded if it becomes 0. However, the destination node should process the packet normally
	// even if received with a hop limit of 0.
	HopLimit uint8
	SrcIP    netip.Addr // The unicast IPv6 address of the sending node.
	DstIP    netip.Addr // The IPv6 unicast or multicast address of the destination node(s).
	payload  []byte
}

func (p *IPv6Packet) String() string {
	return fmt.Sprintf(`%s
- Version: %d
- Traffic Class: %s
- Payload Length: %d
- Next Header: %s (%d)
- Hop Limit: %d
- SrcIP: %s
- DstIP: %s
- Payload: %d bytes
`,
		p.Summary(),
		p.Version,
		p.TrafficClass,
		p.PayloadLength,
		p.NextHeaderDesc,
		p.NextHeader,
		p.HopLimit,
		p.SrcIP,
		p.DstIP,
		len(p.payload),
	)
}

func (p *IPv6Packet) Summary() string {
	return fmt.Sprintf("IPv6 Packet: Src IP: %s →  Dst IP: %s", p.SrcIP, p.DstIP)
}

// Parse parses the given byte data into an IPv6 packet struct.
func (p *IPv6Packet) Parse(data []byte) error {
	if len(data) < headerSizeIPv6 {
		return fmt.Errorf("minimum header size for IPv6 is %d bytes, got %d bytes", headerSizeIPv6, len(data))
	}
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	versionTrafficFlow := binary.BigEndian.Uint32(buf[0:4])
	p.Version = uint8(versionTrafficFlow >> 28)
	p.TrafficClass = newTrafficiClass(uint8((versionTrafficFlow >> 20) & 0xFF))
	p.FlowLabel = versionTrafficFlow & (1<<20 - 1)
	p.PayloadLength = binary.BigEndian.Uint16(buf[4:6])
	p.NextHeader = buf[6]
	p.NextHeaderDesc = p.nextHeader()
	p.HopLimit = buf[7]
	p.SrcIP, _ = netip.AddrFromSlice(buf[8:24])
	p.DstIP, _ = netip.AddrFromSlice(buf[24:headerSizeIPv6])
	p.payload = buf[headerSizeIPv6:]
	return nil
}

func (p *IPv6Packet) NextLayer() (string, []byte) {
	// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	var layer string
	switch p.NextHeader {
	case 6:
		layer = "TCP"
	case 17:
		layer = "UDP"
	case 58:
		layer = "ICMPv6"
	default:
		layer = ""
	}
	return layer, p.payload
}

func (p *IPv6Packet) nextHeader() string {
	// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	var header string
	switch p.NextHeader {
	case 0:
		header = "HOPOPT"
	case 6:
		header = "TCP"
	case 17:
		header = "UDP"
	case 43:
		header = "Route"
	case 44:
		header = "Fragment"
	case 50:
		header = "Encapsulating Security payload"
	case 51:
		header = "Authentication Header"
	case 58:
		header = "ICMPv6"
	case 59:
		header = "NoNxt"
	case 60:
		header = "Opts"
	case 135:
		header = "Mobility"
	case 139:
		header = "Host Identity Protocol"
	case 140:
		header = "Shim6 Protocol"
	default:
		header = ""
	}
	return header
}
