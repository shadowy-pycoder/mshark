package layers

import (
	"encoding/binary"
	"fmt"
)

const (
	headerSizeUDP           = 8
	headerChecksumOffsetUDP = 18
)

type UDPSegment struct {
	// UDP protocol is defined in RFC 768.
	SrcPort   uint16 // Identifies the sending port.
	DstPort   uint16 // Identifies the receiving port.
	UDPLength uint16 // Specifies the length in bytes of the UDP header and UDP data.
	Checksum  uint16 // The checksum field may be used for error-checking of the header and data.
	Payload   []byte
}

func NewUDPSegment(srcPort, dstPort uint16, payload []byte) (*UDPSegment, error) {
	udp := &UDPSegment{SrcPort: srcPort, DstPort: dstPort, UDPLength: uint16(headerSizeUDP + len(payload)), Payload: payload}
	return udp, nil
}

func (u *UDPSegment) String() string {
	return fmt.Sprintf(`%s
- SrcPort: %d
- DstPort: %d
- UDP Length: %d
- Checksum: %#04x
- Payload: %d bytes
`,
		u.Summary(),
		u.SrcPort,
		u.DstPort,
		u.UDPLength,
		u.Checksum,
		len(u.Payload),
	)
}

func (u *UDPSegment) Summary() string {
	return fmt.Sprintf("UDP Segment: Src Port: %d →  Dst Port: %d Len: %d", u.SrcPort, u.DstPort, len(u.Payload))
}

func (u *UDPSegment) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2+2+2+2+len(u.Payload))
	binary.BigEndian.PutUint16(b[0:2], u.SrcPort)
	binary.BigEndian.PutUint16(b[2:4], u.DstPort)
	binary.BigEndian.PutUint16(b[4:6], u.UDPLength)
	binary.BigEndian.PutUint16(b[6:headerSizeUDP], u.Checksum)
	copy(b[headerSizeUDP:], u.Payload)
	return b, nil
}

func (u *UDPSegment) ToBytes() []byte {
	b, _ := u.MarshalBinary()
	return b
}

func (u *UDPSegment) UnmarshalBinary(data []byte) error {
	if len(data) < headerSizeUDP {
		return fmt.Errorf("minimum header size for UDP is %d bytes, got %d bytes", headerSizeUDP, len(data))
	}
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	u.SrcPort = binary.BigEndian.Uint16(buf[0:2])
	u.DstPort = binary.BigEndian.Uint16(buf[2:4])
	u.UDPLength = binary.BigEndian.Uint16(buf[4:6])
	u.Checksum = binary.BigEndian.Uint16(buf[6:headerSizeUDP])
	u.Payload = buf[headerSizeUDP:]
	return nil
}

// Parse parses the given byte data into a UDPSegment struct.
func (u *UDPSegment) Parse(data []byte) error {
	return u.UnmarshalBinary(data)
}

func (u *UDPSegment) NextLayer() Layer {
	return ParseNextLayer(u.Payload, &u.SrcPort, &u.DstPort)
}

func (u *UDPSegment) Name() LayerName { return LayerUDP }

func (u *UDPSegment) SetChecksum(pseudo []byte) error {
	// TODO: add support for IPv6, calculate offset
	checksum, err := CalculateInternetChecksum(append(pseudo, u.ToBytes()...), headerChecksumOffsetUDP)
	if err != nil {
		return err
	}
	u.Checksum = checksum
	return nil
}
