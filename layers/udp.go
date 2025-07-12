package layers

import (
	"encoding/binary"
	"fmt"
)

const headerSizeUDP = 8

// UDP protocol is defined in RFC 768.
type UDPSegment struct {
	SrcPort   uint16 // Identifies the sending port.
	DstPort   uint16 // Identifies the receiving port.
	UDPLength uint16 // Specifies the length in bytes of the UDP header and UDP data.
	Checksum  uint16 // The checksum field may be used for error-checking of the header and data.
	payload   []byte
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
		len(u.payload),
	)
}

func (u *UDPSegment) Summary() string {
	return fmt.Sprintf("UDP Segment: Src Port: %d →  Dst Port: %d Len: %d", u.SrcPort, u.DstPort, len(u.payload))
}

// Parse parses the given byte data into a UDPSegment struct.
func (u *UDPSegment) Parse(data []byte) error {
	if len(data) < headerSizeUDP {
		return fmt.Errorf("minimum header size for UDP is %d bytes, got %d bytes", headerSizeUDP, len(data))
	}
	u.SrcPort = binary.BigEndian.Uint16(data[0:2])
	u.DstPort = binary.BigEndian.Uint16(data[2:4])
	u.UDPLength = binary.BigEndian.Uint16(data[4:6])
	u.Checksum = binary.BigEndian.Uint16(data[6:headerSizeUDP])
	u.payload = data[headerSizeUDP:]
	return nil
}

func (u *UDPSegment) NextLayer() (string, []byte) {
	return nextAppLayer(u.SrcPort, u.DstPort), u.payload
}
