package layers

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const headerSizeIPv6 = 40

func NewIPv6Proto(proto IPProto) *IPProtocol {
	pdesc := nextHeader(proto)
	if pdesc == "Unknown" {
		return nil
	}
	return &IPProtocol{Val: proto, Desc: pdesc}
}

type TrafficClass struct {
	Raw      uint8
	DSCP     uint8
	DSCPDesc string
	ECN      uint8
}

func NewTrafficClass(tc uint8) *TrafficClass {
	dscpbin := tc >> 2
	ddesc := dscpdesc(dscpbin)
	if ddesc == "Unknown" {
		return nil
	}
	return &TrafficClass{
		Raw:      tc,
		DSCP:     dscpbin,
		DSCPDesc: ddesc,
		ECN:      tc & 3,
	}
}

func (p *TrafficClass) String() string {
	return fmt.Sprintf("%#02x DSCP: %s (%#06b) ECN: %#02b", p.Raw, p.DSCPDesc, p.DSCP, p.ECN)
}

// IPv6Packet is the smallest message entity exchanged using Internet Protocol version 6 (IPv6).
// IPv6 protocol defined in RFC 2460.
type IPv6Packet struct {
	Version       uint8         // 4 bits version field (for IPv6, this is always equal to 6).
	TrafficClass  *TrafficClass // 6 + 2 bits holds DS and ECN values.
	FlowLabel     uint32        // 20 bits high-entropy identifier of a flow of packets between a source and destination.
	PayloadLength uint16        // 16 bits the size of the payload in octets, including any extension headers.
	NextHeader    *IPProtocol   // 8 bits specifies the type of the next header.
	// 8 bits replaces the time to live field in IPv4. This value is decremented by one at each forwarding node
	// and the packet is discarded if it becomes 0. However, the destination node should process the packet normally
	// even if received with a hop limit of 0.
	HopLimit uint8
	SrcIP    netip.Addr // The unicast IPv6 address of the sending node.
	DstIP    netip.Addr // The IPv6 unicast or multicast address of the destination node(s).
	Payload  []byte
}

func NewIPv6Packet(srcIP, dstIP netip.Addr, proto IPProto, payload []byte) (*IPv6Packet, error) {
	// NOTE: extension headers are not supported
	if !srcIP.IsValid() || !srcIP.Is6() || !dstIP.IsValid() || !dstIP.Is6() {
		return nil, fmt.Errorf("malformed IPv6 address")
	}
	ipproto := NewIPv6Proto(proto)
	if ipproto == nil {
		return nil, fmt.Errorf("malformed proto")
	}
	ipv6Packet := &IPv6Packet{
		Version:       6,
		TrafficClass:  NewTrafficClass(0),
		PayloadLength: uint16(len(payload)),
		NextHeader:    ipproto,
		HopLimit:      255,
		SrcIP:         srcIP,
		DstIP:         dstIP,
		Payload:       payload,
	}
	return ipv6Packet, nil
}

func (p *IPv6Packet) String() string {
	return fmt.Sprintf(`%s
- Version: %d
- Traffic Class: %s
- Payload Length: %d
- Next Header: %s
- Hop Limit: %d
- SrcIP: %s
- DstIP: %s
- Payload: %d bytes
`,
		p.Summary(),
		p.Version,
		p.TrafficClass,
		p.PayloadLength,
		p.NextHeader,
		p.HopLimit,
		p.SrcIP,
		p.DstIP,
		len(p.Payload),
	)
}

func (p *IPv6Packet) Summary() string {
	return fmt.Sprintf("IPv6 Packet: Src IP: %s →  Dst IP: %s", p.SrcIP, p.DstIP)
}

func (p *IPv6Packet) MarshalBinary() ([]byte, error) {
	b := make([]byte, 4+2+1+1+16+16 /* headerSizeIPv6 */ +len(p.Payload))
	binary.BigEndian.PutUint32(b[0:4], uint32(p.Version)<<28|uint32(p.TrafficClass.Raw)<<20|p.FlowLabel)
	binary.BigEndian.PutUint16(b[4:6], p.PayloadLength)
	b[6] = uint8(p.NextHeader.Val)
	b[7] = p.HopLimit
	copy(b[8:24], p.SrcIP.AsSlice())
	copy(b[24:headerSizeIPv6], p.DstIP.AsSlice())
	copy(b[headerSizeIPv6:], p.Payload)
	return b, nil
}

func (p *IPv6Packet) ToBytes() []byte {
	b, _ := p.MarshalBinary()
	return b
}

func (p *IPv6Packet) UnmarshalBinary(data []byte) error {
	if len(data) < headerSizeIPv6 {
		return fmt.Errorf("minimum header size for IPv6 is %d bytes, got %d bytes", headerSizeIPv6, len(data))
	}
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	versionTrafficFlow := binary.BigEndian.Uint32(buf[0:4])
	p.Version = uint8(versionTrafficFlow >> 28)
	if p.Version != 6 {
		return fmt.Errorf("unknown version")
	}
	tc := NewTrafficClass(uint8((versionTrafficFlow >> 20) & 0xFF))
	if tc == nil {
		return fmt.Errorf("malformed traffic class")
	}
	p.TrafficClass = tc
	p.FlowLabel = versionTrafficFlow & (1<<20 - 1)
	p.PayloadLength = binary.BigEndian.Uint16(buf[4:6])
	proto := NewIPv6Proto(IPProto(buf[6]))
	if proto == nil {
		return fmt.Errorf("malformed IPv6 proto")
	}
	p.NextHeader = proto
	p.HopLimit = buf[7]
	var ok bool
	p.SrcIP, ok = netip.AddrFromSlice(buf[8:24])
	if !ok {
		return fmt.Errorf("malformed IPv6 address")
	}
	p.DstIP, ok = netip.AddrFromSlice(buf[24:headerSizeIPv6])
	if !ok {
		return fmt.Errorf("malformed IPv6 address")
	}
	p.Payload = buf[headerSizeIPv6:]
	if p.PayloadLength != 0 && int(p.PayloadLength) != len(p.Payload) { // NOTE: this condition does not always mean malformed IPv6
		return fmt.Errorf("payload length field is not equal to actual payload size")
	}
	return nil
}

// Parse parses the given byte data into an IPv6 packet struct.
func (p *IPv6Packet) Parse(data []byte) error {
	return p.UnmarshalBinary(data)
}

func nextLayer(proto IPProto) string {
	// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	var layer string
	switch proto {
	case 6:
		layer = "TCP"
	case 17:
		layer = "UDP"
	case 58:
		layer = "ICMPv6"
	default:
		layer = ""
	}
	return layer
}

func (p *IPv6Packet) NextLayer() Layer {
	if next := GetLayer(LayerName(nextLayer(p.NextHeader.Val))); next != nil {
		if err := next.Parse(p.Payload); err == nil {
			return next
		}
	}
	return ParseNextLayer(p.Payload, nil, nil)
}

func (p *IPv6Packet) Name() LayerName { return LayerIPv6 }

func nextHeader(proto IPProto) string {
	// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	var header string
	switch proto {
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
		header = "Unknown"
	}
	return header
}

type IPv6PseudoHeader struct {
	SrcIP                  netip.Addr
	DstIP                  netip.Addr
	UpperLayerPacketLength uint32
	NextHeader             *IPProtocol
}

func (p *IPv6Packet) PseudoHeader() *IPv6PseudoHeader {
	return &IPv6PseudoHeader{SrcIP: p.SrcIP, DstIP: p.DstIP, UpperLayerPacketLength: uint32(len(p.Payload)), NextHeader: p.NextHeader}
}

func (p *IPv6Packet) SetPayload(payload []byte) {
	p.Payload = payload
}

func (ph *IPv6PseudoHeader) MarshalBinary() ([]byte, error) {
	b := make([]byte, 16+16+4+3+1)
	copy(b[0:16], ph.SrcIP.AsSlice())
	copy(b[16:32], ph.DstIP.AsSlice())
	binary.BigEndian.PutUint32(b[32:36], ph.UpperLayerPacketLength)
	// 3 byte padding
	b[39] = uint8(ph.NextHeader.Val)
	return b, nil
}

func (ph *IPv6PseudoHeader) ToBytes() []byte {
	b, _ := ph.MarshalBinary()
	return b
}
