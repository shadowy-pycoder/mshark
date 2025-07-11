package layers

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

const headerSizeARP = 28

type Operation uint16

const (
	OperationRequest Operation = 1
	OperationReply   Operation = 2
)

type ARPOperation struct {
	Val  Operation
	Desc string
}

func (ao *ARPOperation) String() string {
	return fmt.Sprintf("%s (%d)", ao.Desc, ao.Val)
}

// ARPPacket represents The Address Resolution Protocol (ARP) that is a communication protocol
// used for discovering the link layer address, such as a MAC address,
// associated with a given internet layer address, typically an IPv4 address.
// Defined in RFC 826.
type ARPPacket struct {
	HardwareType     uint16        // Network link protocol type.
	ProtocolType     uint16        // Internetwork protocol for which the ARP request is intended.
	ProtocolTypeDesc string        // Internetwork protocol description.
	Hlen             uint8         // Length (in octets) of a hardware address.
	Plen             uint8         // Length (in octets) of internetwork addresses.
	Op               *ARPOperation // Specifies the operation that the sender is performing.
	// Media address of the sender. In an ARP request this field is used to indicate
	// the address of the host sending the request. In an ARP reply this field is used
	// to indicate the address of the host that the request was looking for.
	SenderMAC net.HardwareAddr
	SenderIP  netip.Addr // Internetwork address of the sender.
	// Media address of the intended receiver. In an ARP request this field is ignored.
	// In an ARP reply this field is used to indicate the address of the host that originated the ARP request.
	TargetMAC net.HardwareAddr
	TargetIP  netip.Addr // Internetwork address of the intended receiver.
}

func NewARPPacket(
	op Operation,
	senderMAC net.HardwareAddr,
	senderIP netip.Addr,
	targetMAC net.HardwareAddr,
	targetIP netip.Addr,
) (*ARPPacket, error) {
	if len(senderMAC) < 6 || len(targetMAC) < 6 || len(senderMAC) != len(targetMAC) {
		return nil, fmt.Errorf("malformed hardware address")
	}
	if !senderIP.IsValid() || !senderIP.Is4() || !targetIP.IsValid() || !targetIP.Is4() {
		return nil, fmt.Errorf("malformed protocol address")
	}
	return &ARPPacket{
		HardwareType:     1,
		ProtocolType:     0x0800,
		ProtocolTypeDesc: "IPv4",
		Hlen:             uint8(len(senderMAC)),
		Plen:             4,
		Op:               &ARPOperation{Val: op, Desc: opdesc(op)},
		SenderMAC:        senderMAC,
		SenderIP:         senderIP,
		TargetMAC:        targetMAC,
		TargetIP:         targetIP,
	}, nil
}

func (ap *ARPPacket) String() string {
	return fmt.Sprintf(`%s
- Hardware Type: %d
- Protocol Type: %s (%#04x)
- HLen: %d
- PLen: %d
- Operation: %s
- Sender MAC Address: %s
- Sender IP Address: %s
- Target MAC Address: %s
- Target IP Address: %s
`,
		ap.Summary(),
		ap.HardwareType,
		ap.ProtocolTypeDesc,
		ap.ProtocolType,
		ap.Hlen,
		ap.Plen,
		ap.Op,
		ap.SenderMAC,
		ap.SenderIP,
		ap.TargetMAC,
		ap.TargetIP,
	)
}

func (ap *ARPPacket) Summary() string {
	var message string
	switch ap.Op.Val {
	case OperationRequest:
		message = fmt.Sprintf("ARP Packet: (%s) Who has %s? Tell %s", ap.Op.Desc, ap.TargetIP, ap.SenderIP)
	case OperationReply:
		message = fmt.Sprintf("ARP Packet: (%s) %s is at %s", ap.Op.Desc, ap.SenderIP, ap.SenderMAC)
	default:
		message = fmt.Sprintf("ARP Packet: (%s)", ap.Op.Desc)
	}
	return message
}

// MarshalBinary implements encoding.BinaryMarshaler interface
func (ap *ARPPacket) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2+2+1+1+2+(ap.Plen*2)+(ap.Hlen*2))
	binary.BigEndian.PutUint16(b[0:2], ap.HardwareType)
	binary.BigEndian.PutUint16(b[2:4], ap.ProtocolType)
	b[4] = ap.Hlen
	b[5] = ap.Plen
	binary.BigEndian.PutUint16(b[6:8], uint16(ap.Op.Val))
	hoffset := 8 + ap.Hlen
	poffset := hoffset + ap.Plen
	copy(b[8:hoffset], ap.SenderMAC)
	copy(b[hoffset:poffset], ap.SenderIP.AsSlice())
	copy(b[poffset:poffset+ap.Hlen], ap.TargetMAC)
	copy(b[poffset+ap.Hlen:poffset+ap.Hlen+ap.Plen], ap.TargetIP.AsSlice())
	return b, nil
}

func (ap *ARPPacket) ToBytes() []byte {
	b, _ := ap.MarshalBinary()
	return b
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler interface
func (ap *ARPPacket) UnmarshalBinary(data []byte) error {
	if len(data) < headerSizeARP {
		return fmt.Errorf("minimum header size for ARP is %d bytes, got %d bytes", headerSizeARP, len(data))
	}
	ap.HardwareType = binary.BigEndian.Uint16(data[0:2])
	ap.ProtocolType = binary.BigEndian.Uint16(data[2:4])
	ap.ProtocolTypeDesc = ptypedesc(ap.ProtocolType)
	if ap.ProtocolTypeDesc == "Unknown" {
		return fmt.Errorf("unknown protocol type")
	}
	ap.Hlen = data[4]
	ap.Plen = data[5]
	op := Operation(binary.BigEndian.Uint16(data[6:8]))
	opdesc := opdesc(op)
	if opdesc == "Unknown" {
		return fmt.Errorf("unknown operation")
	}
	ap.Op = &ARPOperation{Val: op, Desc: opdesc}
	hoffset := 8 + ap.Hlen
	ap.SenderMAC = net.HardwareAddr(data[8:hoffset])
	poffset := hoffset + ap.Plen
	var ok bool
	ap.SenderIP, ok = netip.AddrFromSlice(data[hoffset:poffset])
	if !ok {
		return fmt.Errorf("failed parsing sender IP address")
	}
	ap.TargetMAC = net.HardwareAddr(data[poffset : poffset+ap.Hlen])
	ap.TargetIP, ok = netip.AddrFromSlice(data[poffset+ap.Hlen : poffset+ap.Hlen+ap.Plen])
	if !ok {
		return fmt.Errorf("failed parsing target IP address")
	}
	return nil
}

// Parse parses the given ARP packet data into the ARPPacket struct.
func (ap *ARPPacket) Parse(data []byte) error {
	return ap.UnmarshalBinary(data)
}

func (ap *ARPPacket) NextLayer() (layer string, payload []byte) { return }

func ptypedesc(pt uint16) string {
	var proto string
	switch pt {
	case 0x0800:
		proto = "IPv4"
	case 0x86dd:
		proto = "IPv6"
	default:
		proto = "Unknown"
	}
	return proto
}

func opdesc(op Operation) string {
	var opdesc string
	switch op {
	case OperationRequest:
		opdesc = "request"
	case OperationReply:
		opdesc = "reply"
	default:
		opdesc = "Unknown"
	}
	return opdesc
}
