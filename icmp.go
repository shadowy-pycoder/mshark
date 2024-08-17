package minishark

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const headerSizeICMP = 4

type ICMPSegment struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Payload  []byte
}

func (i *ICMPSegment) String() string {
	mtype, code := i.typecode()
	return fmt.Sprintf(`ICMP Segment:
- Type: %d (%s)
- Code: %d (%s)
- Checksum: %#04x
%s
`,
		i.Type,
		mtype,
		i.Code,
		code,
		i.Checksum,
		i.payload(),
	)
}

func (i *ICMPSegment) Parse(data []byte) error {
	if len(data) < headerSizeICMP {
		return fmt.Errorf("minimum header size for ICMP is %d bytes, got %d bytes", headerSizeICMP, len(data))
	}
	i.Type = data[0]
	i.Code = data[1]
	i.Checksum = binary.BigEndian.Uint16(data[2:4])
	i.Payload = data[headerSizeICMP:]
	return nil
}

func (i *ICMPSegment) typecode() (string, string) {
	// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
	var mtype, code string
	switch i.Type {
	case 0:
		mtype = "Echo Reply"
		code = "Echo Reply (Ping)"
	case 3:
		mtype = "Destination Unreachable"
		switch i.Code {
		case 0:
			code = "Echo Reply (Ping)"
		case 1:
			code = "Destination host unreachable"
		case 2:
			code = "Destination protocol unreachable"
		case 3:
			code = "Destination port unreachable"
		case 4:
			code = "Fragmentation required, and DF flag set"
		case 5:
			code = "Source route failed"
		case 6:
			code = "Destination network unknown"
		case 7:
			code = "Destination host unknown"
		case 8:
			code = "Source host isolated"
		case 9:
			code = "Network administratively prohibited"
		case 10:
			code = "Host administratively prohibited"
		case 11:
			code = "Network unreachable for ToS"
		case 12:
			code = "Host unreachable for ToS"
		case 13:
			code = "Communication administratively prohibited"
		case 14:
			code = "Host Precedence Violation"
		case 15:
			code = "Precedence cutoff in effect"
		default:
			code = "Unknown"
		}
	case 5:
		mtype = "Redirect Message"
		switch i.Code {
		case 0:
			code = "Redirect Datagram for the Network"
		case 1:
			code = "Redirect Datagram for the Host"
		case 2:
			code = "Redirect Datagram for the ToS & network"
		case 3:
			code = "Redirect Datagram for the ToS & host"
		default:
			code = "Unknown"
		}
	case 8:
		mtype = "Echo Request"
		code = "Echo Request (Ping)"
	case 9:
		mtype = "Router Advertisement"
		code = "Router Advertisement"
	case 10:
		mtype = "Router Solicitation"
		code = "Router discovery/selection/solicitation"
	case 11:
		mtype = "Time Exceeded"
		switch i.Code {
		case 0:
			code = "Time to live (TTL) expired in transit"
		case 1:
			code = "Fragment reassembly time exceeded"
		default:
			code = "Unknown"
		}
	case 12:
		mtype = "Parameter Problem: Bad IP header"
		switch i.Code {
		case 0:
			code = "Pointer indicates the error"
		case 1:
			code = "Missing a required option"
		case 2:
			code = "Bad length"
		default:
			code = "Unknown"
		}
	case 13:
		mtype = "Timestamp"
		code = "Timestamp"
	case 14:
		mtype = "Timestamp Reply"
		code = "Timestamp Reply"
	case 42:
		mtype = "Extended Echo Request"
		code = "Extended Echo Request"
	case 43:
		mtype = "Extended Echo Reply"
		switch i.Code {
		case 0:
			code = "No Error"
		case 1:
			code = "Malformed Query"
		case 2:
			code = "No Such Interface"
		case 3:
			code = "No Such Table Entry"
		case 4:
			code = "Multiple Interfaces Satisfy Query"
		default:
			code = "Unknown"
		}
	default:
		mtype = "Unknown"
	}
	return mtype, code
}

func (i *ICMPSegment) payload() string {
	var payload string
	switch i.Type {
	case 0, 8:
		payload = fmt.Sprintf(`- Identifier: %d
- Sequence Number: %d
- Data: (%d bytes) %x`,
			binary.BigEndian.Uint16(i.Payload[0:2]),
			binary.BigEndian.Uint16(i.Payload[2:4]),
			len(i.Payload[4:]), i.Payload[4:])
	case 3, 11:
		payload = fmt.Sprintf(`- Reserved: %#08x
- Data: (%d bytes) %x`,
			binary.BigEndian.Uint32(i.Payload[0:4]), len(i.Payload[4:]), i.Payload[4:])
	case 5:
		gatewayAddress, _ := netip.AddrFromSlice(i.Payload[0:4])
		payload = fmt.Sprintf(`- Gateway Address: %s
- Data: (%d bytes) %x`, gatewayAddress, len(i.Payload[4:]), i.Payload[4:])
	case 13, 14:
		payload = fmt.Sprintf(`- Identifier: %d
- Sequence Number: %d
- Originate Timestamp: %d
- Receive Timestamp: %d
- Transmit Timestamp: %d
`,
			binary.BigEndian.Uint16(i.Payload[0:2]),
			binary.BigEndian.Uint16(i.Payload[2:4]),
			binary.BigEndian.Uint32(i.Payload[4:8]),
			binary.BigEndian.Uint32(i.Payload[8:12]),
			binary.BigEndian.Uint32(i.Payload[12:16]),
		)
	default:
		payload = fmt.Sprintf(`- Data: (%d bytes) %x`, len(i.Payload), i.Payload)
	}
	return payload
}
