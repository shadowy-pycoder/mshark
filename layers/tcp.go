package layers

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const headerSizeTCP = 20

var tcpFlags = []string{"CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"}

type TCPFlag struct {
	Val  uint8
	Desc string
}

type TCPFlags struct {
	Raw uint8
	Val []*TCPFlag
}

func (t *TCPFlags) String() string {
	var sb strings.Builder
	for _, flag := range t.Val {
		if flag.Val == 1 {
			sb.WriteString(flag.Desc)
			sb.WriteString(" ")
		}
	}
	return strings.TrimSpace(sb.String())
}

func newTCPFlags(flags uint8) *TCPFlags {
	f := TCPFlags{Raw: flags, Val: make([]*TCPFlag, 0, 8)}
	for i, flag := range tcpFlags {
		f.Val = append(f.Val, &TCPFlag{Val: (flags >> (7 - i)) & 1, Desc: flag})
	}
	return &f
}

// TCP protocol is described in RFC 761.
type TCPSegment struct {
	SrcPort uint16 // Identifies the sending port.
	DstPort uint16 // Identifies the receiving port.
	// If the SYN flag is set (1), then this is the initial sequence number. The sequence number of the actual
	// first data byte and the acknowledged number in the corresponding ACK are then this sequence number plus 1.
	// If the SYN flag is unset (0), then this is the accumulated sequence number of the first data byte of this
	// segment for the current session.
	SeqNumber uint32
	// If the ACK flag is set, the value is the next sequence number that the sender of the ACK is expecting.
	AckNumber  uint32
	DataOffset uint8     // 4 bits specifies the size of the TCP header in 32-bit words.
	Reserved   uint8     // 4 bits reserved for future use and should be set to zero.
	Flags      *TCPFlags // Contains 8 1-bit flags (control bits)
	// The size of the receive window, which specifies the number of window size units[b] that the sender of
	// this segment is currently willing to receive.
	WindowSize uint16
	// The 16-bit checksum field is used for error-checking of the TCP header, the payload and an IP pseudo-header.
	Checksum uint16
	// If the URG flag is set, then this 16-bit field is an offset from the sequence number
	// indicating the last urgent data byte.
	UrgentPointer uint16
	Options       []byte // The length of this field is determined by the data offset field.
	payload       []byte
}

func (t *TCPSegment) String() string {
	return fmt.Sprintf(`%s
- SrcPort: %d
- DstPort: %d
- Sequence Number: %d
- Acknowledgment Number: %d
- Data Offset: %d
- Reserved: %d
- Flags: %s (%#08b)
- Window Size: %d
- Checksum: %#04x
- Urgent Pointer: %d
- Options: (%d bytes) %x
- Payload: %d bytes
`,
		t.Summary(),
		t.SrcPort,
		t.DstPort,
		t.SeqNumber,
		t.AckNumber,
		t.DataOffset,
		t.Reserved,
		t.Flags,
		t.Flags.Raw,
		t.WindowSize,
		t.Checksum,
		t.UrgentPointer,
		len(t.Options),
		t.Options,
		len(t.payload),
	)
}

func (t *TCPSegment) Summary() string {
	return fmt.Sprintf(
		"TCP Segment: Src Port: %d →  Dst Port: %d [%s] Win: %d Len: %d",
		t.SrcPort,
		t.DstPort,
		t.Flags,
		t.WindowSize,
		len(t.payload),
	)
}

// Parse parses the given byte data into a TCPSegment struct.
func (t *TCPSegment) Parse(data []byte) error {
	if len(data) < headerSizeTCP {
		return fmt.Errorf("minimum header size for TCP is %d bytes, got %d bytes", headerSizeTCP, len(data))
	}
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	t.SrcPort = binary.BigEndian.Uint16(buf[0:2])
	t.DstPort = binary.BigEndian.Uint16(buf[2:4])
	t.SeqNumber = binary.BigEndian.Uint32(buf[4:8])
	t.AckNumber = binary.BigEndian.Uint32(buf[8:12])
	offsetReservedFlags := binary.BigEndian.Uint16(buf[12:14])
	t.DataOffset = uint8(offsetReservedFlags >> 12)
	t.Reserved = uint8((offsetReservedFlags >> 8) & 15)
	t.Flags = newTCPFlags(uint8(offsetReservedFlags & (1<<8 - 1)))
	t.WindowSize = binary.BigEndian.Uint16(buf[14:16])
	t.Checksum = binary.BigEndian.Uint16(buf[16:18])
	t.UrgentPointer = binary.BigEndian.Uint16(buf[18:headerSizeTCP])
	t.Options = buf[headerSizeTCP : t.DataOffset<<2]
	t.payload = buf[t.DataOffset<<2:]
	return nil
}

func (t *TCPSegment) NextLayer() (string, []byte) {
	return nextAppLayer(t.SrcPort, t.DstPort), t.payload
}

func nextAppLayer(src, dst uint16) string {
	var layer string
	switch {
	case src == 20 || dst == 20 || src == 21 || dst == 21:
		layer = "FTP"
	case src == 22 || dst == 22:
		layer = "SSH"
	case src == 53 || dst == 53:
		layer = "DNS"
	case src == 80 || dst == 80:
		layer = "HTTP"
	case src == 161 || dst == 161 || src == 162 || dst == 162:
		layer = "SNMP"
	case src == 443 || dst == 443:
		layer = "TLS"
	default:
		layer = ""
	}
	return layer
}
