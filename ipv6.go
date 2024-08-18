package minishark

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const headerSizeIPv6 = 40

// An IPv6 packet is the smallest message entity exchanged using Internet Protocol version 6 (IPv6).
// IPv6 protocol defined in RFC 2460.
type IPv6Packet struct {
	Version       uint8  // 4 bits version field (for IPv6, this is always equal to 6).
	TrafficClass  uint8  // 6 + 2 bits holds DS and ECN values.
	FlowLabel     uint32 // 20 bits high-entropy identifier of a flow of packets between a source and destination.
	PayloadLength uint16 // 16 bits the size of the payload in octets, including any extension headers.
	NextHeader    uint8  // 8 bits specifies the type of the next header.
	// 8 bits replaces the time to live field in IPv4. This value is decremented by one at each forwarding node
	// and the packet is discarded if it becomes 0. However, the destination node should process the packet normally
	// even if received with a hop limit of 0.
	HopLimit uint8
	SrcIP    netip.Addr // The unicast IPv6 address of the sending node.
	DstIP    netip.Addr // The IPv6 unicast or multicast address of the destination node(s).
	Payload  []byte
}

func (p *IPv6Packet) String() string {
	return fmt.Sprintf(`IPv6 Packet:
- Version: %d
- Traffic Class: %s
- Payload Length: %d
- Next Header: %s (%d)
- Hop Limit: %d
- SrcIP: %s
- DstIP: %s
- Payload: (%d bytes) %x 
`,
		p.Version,
		p.trafficClass(),
		p.PayloadLength,
		p.NextLayer(),
		p.NextHeader,
		p.HopLimit,
		p.SrcIP,
		p.DstIP,
		len(p.Payload),
		p.Payload,
	)
}

// Parse parses the given byte data into an IPv6 packet struct.
func (p *IPv6Packet) Parse(data []byte) error {
	if len(data) < headerSizeIPv6 {
		return fmt.Errorf("minimum header size for IPv6 is %d bytes, got %d bytes", headerSizeIPv6, len(data))
	}
	versionTrafficFlow := binary.BigEndian.Uint32(data[0:4])
	p.Version = uint8(versionTrafficFlow >> 28)
	p.TrafficClass = uint8((versionTrafficFlow >> 20) & 0xFF)
	p.FlowLabel = versionTrafficFlow & (1<<20 - 1)
	p.PayloadLength = binary.BigEndian.Uint16(data[4:6])
	p.NextHeader = data[6]
	p.HopLimit = data[7]
	p.SrcIP, _ = netip.AddrFromSlice(data[8:24])
	p.DstIP, _ = netip.AddrFromSlice(data[24:headerSizeIPv6])
	p.Payload = data[headerSizeIPv6:]
	return nil
}

// NextLayer returns the type of the next header.
func (p *IPv6Packet) NextLayer() string {
	// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	var proto string
	switch p.NextHeader {
	case 0:
		proto = "HOPOPT"
	case 6:
		proto = "TCP"
	case 17:
		proto = "UDP"
	case 43:
		proto = "Route"
	case 44:
		proto = "Fragment"
	case 50:
		proto = "Encapsulating Security Payload"
	case 51:
		proto = "Authentication Header"
	case 58:
		proto = "ICMPv6"
	case 59:
		proto = "NoNxt"
	case 60:
		proto = "Opts"
	case 135:
		proto = "Mobility"
	case 139:
		proto = "Host Identity Protocol"
	case 140:
		proto = "Shim6 Protocol"
	default:
		proto = "Unknown"
	}
	return proto
}

func (p *IPv6Packet) trafficClass() string {
	// https://en.wikipedia.org/wiki/Differentiated_services
	var dscp string
	dscpbin := p.TrafficClass >> 2
	switch dscpbin {
	case 0:
		dscp = "Standard (DF)"
	case 1:
		dscp = "Lower-effort (LE)"
	case 48:
		dscp = "Network control (CS6)"
	case 46:
		dscp = "Telephony (EF)"
	case 40:
		dscp = "Signaling (CS5)"
	case 34, 36, 38:
		dscp = "Multimedia conferencing (AF41, AF42, AF43)"
	case 32:
		dscp = "Real-time interactive (CS4)"
	case 26, 28, 30:
		dscp = "Multimedia streaming (AF31, AF32, AF33)"
	case 24:
		dscp = "Broadcast video (CS3)"
	case 18, 20, 22:
		dscp = "Low-latency data (AF21, AF22, AF23)"
	case 16:
		dscp = "OAM (CS2)"
	case 10, 12, 14:
		dscp = "High-throughput data (AF11, AF12, AF13)"
	default:
		dscp = "Unknown"
	}
	return fmt.Sprintf("%#02x DSCP: %s (%#06b) ECN: %#02b", p.TrafficClass, dscp, dscpbin, p.TrafficClass&3)
}
