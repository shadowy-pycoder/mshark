package layers

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const headerSizeIPv4 = 20

type IPv4Flags struct {
	Reserved uint8
	MF       uint8
	DF       uint8
}

func (i *IPv4Flags) String() string {
	return fmt.Sprintf("Reserved %d DF %d MF %d", i.Reserved, i.MF, i.DF)
}

func newIPv4Flags(flags uint8) *IPv4Flags {
	return &IPv4Flags{
		Reserved: (flags >> 2) & 1,
		DF:       (flags >> 1) & 1,
		MF:       flags & 1,
	}
}

// Internet Protocol version 4 is described in IETF publication RFC 791.
type IPv4Packet struct {
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
	Protocol       uint8      // 8 bits defines the protocol used in the data portion of the IP datagram.
	ProtocolDesc   string     // Protocol description.
	HeaderChecksum uint16     // 16 bits used for error checking of the header.
	SrcIP          netip.Addr // IPv4 address of the sender of the packet.
	DstIP          netip.Addr // IPv4 address of the receiver of the packet.
	Options        []byte     // if ihl > 5
	payload        []byte
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
- Protocol: %s (%d)
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
		p.ProtocolDesc,
		p.Protocol,
		p.HeaderChecksum,
		p.SrcIP,
		p.DstIP,
		p.Options,
		len(p.payload),
	)
}

func (p *IPv4Packet) Summary() string {
	return fmt.Sprintf("IPv4 Packet: Src IP: %s →  Dst IP: %s", p.SrcIP, p.DstIP)
}

// Parse parses the given byte data into an IPv4 packet struct.
func (p *IPv4Packet) Parse(data []byte) error {
	if len(data) < headerSizeIPv4 {
		return fmt.Errorf("minimum header size for IPv4 is %d bytes, got %d bytes", headerSizeIPv4, len(data))
	}
	versionIHL := data[0]
	p.Version = versionIHL >> 4
	p.IHL = versionIHL & 15
	dscpECN := data[1]
	p.DSCP = dscpECN >> 2
	p.DSCPDesc = dscpdesc(p.DSCP)
	p.ECN = dscpECN & 3
	p.TotalLength = binary.BigEndian.Uint16(data[2:4])
	p.Identification = binary.BigEndian.Uint16(data[4:6])
	flagsOffset := binary.BigEndian.Uint16(data[6:8])
	flags := uint8(flagsOffset >> 13)
	p.Flags = newIPv4Flags(flags)
	p.FragmentOffset = flagsOffset & (1<<13 - 1)
	p.TTL = data[8]
	p.Protocol = data[9]
	p.HeaderChecksum = binary.BigEndian.Uint16(data[10:12])
	p.SrcIP, _ = netip.AddrFromSlice(data[12:16])
	p.DstIP, _ = netip.AddrFromSlice(data[16:headerSizeIPv4])
	if p.IHL > 5 {
		offset := headerSizeIPv4 + ((p.IHL - 5) << 2)
		p.Options = data[headerSizeIPv4:offset]
		p.payload = data[offset:]
	} else {
		p.payload = data[headerSizeIPv4:]
	}
	p.ProtocolDesc, _ = p.NextLayer()
	return nil
}

func (p *IPv4Packet) NextLayer() (string, []byte) {
	// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	var layer string
	switch p.Protocol {
	case 1:
		layer = "ICMP"
	case 6:
		layer = "TCP"
	case 17:
		layer = "UDP"
	default:
		layer = ""
	}
	return layer, p.payload
}

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
