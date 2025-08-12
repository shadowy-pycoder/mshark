package layers

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	headerSizeIPv4           = 20
	headerChecksumOffsetIPv4 = 10
)

type IPProto uint8

const (
	ProtoICMP IPProto = 1
	ProtoTCP  IPProto = 6
	ProtoUDP  IPProto = 17
)

type IPv4Proto struct {
	Val  IPProto // 8 bits defines the protocol used in the data portion of the IP datagram.
	Desc string  // Protocol description.
}

func (p *IPv4Proto) String() string {
	return fmt.Sprintf("%s (%d)", p.Desc, p.Val)
}

type IPv4Flags struct {
	Raw      uint8
	Reserved uint8
	DF       uint8
	MF       uint8
}

func (i *IPv4Flags) String() string {
	return fmt.Sprintf("Reserved %d DF %d MF %d", i.Reserved, i.DF, i.MF)
}

func NewIPv4Flags(flags uint8) *IPv4Flags {
	return &IPv4Flags{
		Raw:      flags, // 3 bits
		Reserved: (flags >> 2) & 1,
		DF:       (flags >> 1) & 1,
		MF:       flags & 1,
	}
}

type IPv4Packet struct {
	// Internet Protocol version 4 is described in IETF publication RFC 791.
	Version        uint8      // 4 bits version (for IPv4, this is always equal to 4).
	IHL            uint8      // 4 bits size of header (number of 32-bit words).
	DSCP           uint8      // 6 bits specifies differentiated services.
	DSCPDesc       string     // differentiated services description.
	ECN            uint8      // 2 bits end-to-end notification of network congestion without dropping packets.
	TotalLength    uint16     // 16 bits defines the entire packet size in bytes, including header and data.
	Identification uint16     // 16 bits identifies the group of fragments of a single IP datagram.
	Flags          *IPv4Flags // 3 bits used to control or identify fragments.
	FragmentOffset uint16     // 13 bits offset of a particular fragment.
	TTL            uint8      // 8 bits limits a datagram's lifetime to prevent network failure.
	Protocol       *IPv4Proto
	HeaderChecksum uint16     // 16 bits used for error checking of the header.
	SrcIP          netip.Addr // IPv4 address of the sender of the packet.
	DstIP          netip.Addr // IPv4 address of the receiver of the packet.
	Options        []byte     // if ihl > 5
	Payload        []byte
}

func NewIPv4Packet(srcIP, dstIP netip.Addr, proto IPProto, payload []byte) (*IPv4Packet, error) {
	if !srcIP.IsValid() || !srcIP.Is4() || !dstIP.IsValid() || !dstIP.Is4() {
		return nil, fmt.Errorf("malformed IPv4 address")
	}
	ipPacket := &IPv4Packet{
		Version:        4,
		IHL:            5,
		TotalLength:    uint16(headerSizeIPv4 + len(payload)),
		Identification: MustGenerateRandomUint16NE(),
		Flags:          NewIPv4Flags(2),
		TTL:            128,
		Protocol:       &IPv4Proto{Val: proto, Desc: protodesc(proto)},
		SrcIP:          srcIP,
		DstIP:          dstIP,
		Payload:        payload,
	}
	headerChecksum, err := CalculateIPv4Checksum(ipPacket.ToBytes())
	if err != nil {
		return nil, fmt.Errorf("failed calculating checksum")
	}
	ipPacket.HeaderChecksum = headerChecksum
	return ipPacket, nil
}

func (p *IPv4Packet) String() string {
	return fmt.Sprintf(`%s
- Version: %d
- IHL: %d
- DSCP: %s (%#06b)
- ECN: %#02b
- Total Length: %d
- Identification: %#04x
- Flags: %s
- Fragment Offset: %d
- TTL: %d
- Protocol: %s
- Header Checksum: %#04x
- SrcIP: %s
- DstIP: %s
- Options: %v
- Payload: %d bytes
`,
		p.Summary(),
		p.Version,
		p.IHL,
		p.DSCPDesc,
		p.DSCP,
		p.ECN,
		p.TotalLength,
		p.Identification,
		p.Flags,
		p.FragmentOffset,
		p.TTL,
		p.Protocol,
		p.HeaderChecksum,
		p.SrcIP,
		p.DstIP,
		p.Options,
		len(p.Payload),
	)
}

func (p *IPv4Packet) Summary() string {
	return fmt.Sprintf("IPv4 Packet: Src IP: %s →  Dst IP: %s", p.SrcIP, p.DstIP)
}

func (p *IPv4Packet) MarshalBinary() ([]byte, error) {
	b := make([]byte, 1+1+2+2+2+1+1+2+4+4 /* headerSizeIPv4 */ +len(p.Options)+len(p.Payload))
	b[0] = p.Version<<4 | p.IHL
	b[1] = p.DSCP<<2 | p.ECN
	binary.BigEndian.PutUint16(b[2:4], p.TotalLength)
	binary.BigEndian.PutUint16(b[4:6], p.Identification)
	binary.BigEndian.PutUint16(b[6:8], uint16(p.Flags.Raw)<<13|p.FragmentOffset)
	b[8] = p.TTL
	b[9] = uint8(p.Protocol.Val)
	binary.BigEndian.PutUint16(b[headerChecksumOffsetIPv4:12], p.HeaderChecksum)
	copy(b[12:16], p.SrcIP.AsSlice())
	copy(b[16:headerSizeIPv4], p.DstIP.AsSlice())
	copy(b[headerSizeIPv4:headerSizeIPv4+len(p.Options)], p.Options)
	copy(b[headerSizeIPv4+len(p.Options):], p.Payload)
	return b, nil
}

func (p *IPv4Packet) ToBytes() []byte {
	b, _ := p.MarshalBinary()
	return b
}

func (p *IPv4Packet) UnmarshalBinary(data []byte) error {
	if len(data) < headerSizeIPv4 {
		return fmt.Errorf("minimum header size for IPv4 is %d bytes, got %d bytes", headerSizeIPv4, len(data))
	}
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	versionIHL := buf[0]
	p.Version = versionIHL >> 4
	if p.Version != 4 {
		return fmt.Errorf("unknown version")
	}
	p.IHL = versionIHL & 15
	dscpECN := buf[1]
	p.DSCP = dscpECN >> 2
	p.DSCPDesc = dscpdesc(p.DSCP)
	if p.DSCPDesc == "Unknown" {
		return fmt.Errorf("unknown DSCP")
	}
	p.ECN = dscpECN & 3
	p.TotalLength = binary.BigEndian.Uint16(buf[2:4])
	if int(p.TotalLength) != len(buf) {
		return fmt.Errorf("total length is not equal to actual packet size")
	}
	p.Identification = binary.BigEndian.Uint16(buf[4:6])
	flagsOffset := binary.BigEndian.Uint16(buf[6:8])
	flags := uint8(flagsOffset >> 13)
	p.Flags = NewIPv4Flags(flags)
	p.FragmentOffset = flagsOffset & (1<<13 - 1)
	p.TTL = buf[8]
	proto := IPProto(buf[9])
	protodesc := protodesc(proto)
	if protodesc == "Unknown" {
		return fmt.Errorf("unknown protocol")
	}
	p.Protocol = &IPv4Proto{Val: proto, Desc: protodesc}
	p.HeaderChecksum = binary.BigEndian.Uint16(buf[headerChecksumOffsetIPv4:12])
	var ok bool
	p.SrcIP, ok = netip.AddrFromSlice(buf[12:16])
	if !ok {
		return fmt.Errorf("malformed IPv4 address")
	}
	p.DstIP, ok = netip.AddrFromSlice(buf[16:headerSizeIPv4])
	if !ok {
		return fmt.Errorf("malformed IPv4 address")
	}
	if p.IHL > 5 {
		offset := headerSizeIPv4 + ((p.IHL - 5) << 2)
		if int(offset) > len(buf) {
			return ErrSliceBounds
		}
		p.Options = buf[headerSizeIPv4:offset]
		p.Payload = buf[offset:]
	} else {
		p.Payload = buf[headerSizeIPv4:]
	}
	return nil
}

// Parse parses the given byte data into an IPv4 packet struct.
func (p *IPv4Packet) Parse(data []byte) error {
	return p.UnmarshalBinary(data)
}

func protodesc(proto IPProto) string {
	// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	var protodesc string
	switch proto {
	case 1:
		protodesc = "ICMP"
	case 6:
		protodesc = "TCP"
	case 17:
		protodesc = "UDP"
	default:
		protodesc = "Unknown"
	}
	return protodesc
}

func (p *IPv4Packet) NextLayer() Layer {
	if next := GetLayer(LayerName(p.Protocol.Desc)); next != nil {
		if err := next.Parse(p.Payload); err == nil {
			return next
		}
	}
	return ParseNextLayer(p.Payload, nil, nil)
}

func (p *IPv4Packet) Name() LayerName { return LayerIPv4 }

func dscpdesc(dscp uint8) string {
	// https://en.wikipedia.org/wiki/Differentiated_services
	var dscpdesc string
	switch dscp {
	case 0:
		dscpdesc = "Standard (DF)"
	case 1:
		dscpdesc = "Lower-effort (LE)"
	case 48:
		dscpdesc = "Network control (CS6)"
	case 46:
		dscpdesc = "Telephony (EF)"
	case 40:
		dscpdesc = "Signaling (CS5)"
	case 34, 36, 38:
		dscpdesc = "Multimedia conferencing (AF41, AF42, AF43)"
	case 32:
		dscpdesc = "Real-time interactive (CS4)"
	case 26, 28, 30:
		dscpdesc = "Multimedia streaming (AF31, AF32, AF33)"
	case 24:
		dscpdesc = "Broadcast video (CS3)"
	case 18, 20, 22:
		dscpdesc = "Low-latency data (AF21, AF22, AF23)"
	case 16:
		dscpdesc = "OAM (CS2)"
	case 10, 12, 14:
		dscpdesc = "High-throughput data (AF11, AF12, AF13)"
	default:
		dscpdesc = "Unknown"
	}
	return dscpdesc
}

func CalculateIPv4Checksum(data []byte) (uint16, error) {
	if len(data) < headerSizeIPv4 {
		return 0, fmt.Errorf("minimum header size for IPv4 is %d bytes, got %d bytes", headerSizeIPv4, len(data))
	}
	var sum uint16
	for i := 0; i < headerSizeIPv4; i += 2 {
		if i != headerChecksumOffsetIPv4 {
			sum = add16WithCarryWrapAround(sum, binary.BigEndian.Uint16(data[i:i+2]))
		}
	}
	return ^sum, nil
}

func (p *IPv4Packet) PseudoHeader() *IPv4PseudoHeader {
	return &IPv4PseudoHeader{SrcIP: p.SrcIP, DstIP: p.DstIP, Protocol: p.Protocol, TotalLength: uint16(len(p.Payload))}
}

func (p *IPv4Packet) SetPayload(payload []byte) {
	p.Payload = payload
}

type IPv4PseudoHeader struct {
	SrcIP       netip.Addr
	DstIP       netip.Addr
	Protocol    *IPv4Proto
	TotalLength uint16
}

func (ph *IPv4PseudoHeader) MarshalBinary() ([]byte, error) {
	b := make([]byte, 4+4+1+1+2)
	copy(b[0:4], ph.SrcIP.AsSlice())
	copy(b[4:8], ph.DstIP.AsSlice())
	binary.BigEndian.PutUint16(b[8:10], uint16(ph.Protocol.Val))
	binary.BigEndian.PutUint16(b[10:], ph.TotalLength)
	return b, nil
}

func (ph *IPv4PseudoHeader) ToBytes() []byte {
	b, _ := ph.MarshalBinary()
	return b
}
