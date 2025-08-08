package layers

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const headerSizeICMPv6 = 4

// ICMPv6 is an integral part of IPv6 and performs error reporting and diagnostic functions.
type ICMPv6Segment struct {
	Type     uint8
	TypeDesc string
	Code     uint8
	CodeDesc string
	Checksum uint16
	Data     []byte
}

func (i *ICMPv6Segment) String() string {
	return fmt.Sprintf(`%s
- Type: %d (%s)
- Code: %d (%s)
- Checksum: %#04x
%s
`,
		i.Summary(),
		i.Type,
		i.TypeDesc,
		i.Code,
		i.CodeDesc,
		i.Checksum,
		i.data(),
	)
}

func (i *ICMPv6Segment) Summary() string {
	return fmt.Sprintf("ICMPv6 Segment: %s (%s)", i.TypeDesc, i.CodeDesc)
}

// Parse parses the given byte data into an ICMPv6 segment struct.
func (i *ICMPv6Segment) Parse(data []byte) error {
	if len(data) < headerSizeICMPv6 {
		return fmt.Errorf("minimum header size for ICMPv6 is %d bytes, got %d bytes", headerSizeICMPv6, len(data))
	}
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	i.Type = buf[0]
	i.Code = buf[1]
	i.Checksum = binary.BigEndian.Uint16(buf[2:headerSizeICMPv6])
	i.Data = buf[headerSizeICMPv6:]
	var pLen int
	switch i.Type {
	case 1, 2, 3, 4, 128, 129, 133:
		pLen = 4
	case 134:
		pLen = 12
	case 135, 136:
		pLen = 20
	case 137:
		pLen = 36
	default:
		pLen = len(i.Data)
	}
	if len(i.Data) < pLen {
		return fmt.Errorf("minimum payload length for ICMPv6 with type %d is %d bytes", i.Type, pLen)
	}
	i.TypeDesc, i.CodeDesc = i.typecode()
	return nil
}

func (i *ICMPv6Segment) NextLayer() Layer { return nil }
func (i *ICMPv6Segment) Name() string     { return "ICMPv6" }

func (i *ICMPv6Segment) typecode() (string, string) {
	// https://en.wikipedia.org/wiki/ICMPv6
	var mtype, code string
	switch i.Type {
	case 1:
		mtype = "Destination Unreachable"
		switch i.Code {
		case 0:
			code = "No Route to Destination"
		case 1:
			code = "Communication With Destination Administratively Prohibited"
		case 2:
			code = "Beyond Scope of Source Address"
		case 3:
			code = "Address Unreachable"
		case 4:
			code = "Port Unreachable"
		case 5:
			code = "Source Address Failed Ingress/Egress Policy"
		case 6:
			code = "Reject Route to Destination"
		case 7:
			code = "Error in Source Routing Header"
		default:
			code = "Unknown"
		}
	case 2:
		mtype = "Packet Too Big"
		code = "Packet Too Big"
	case 3:
		mtype = "Time Exceeded"
		switch i.Code {
		case 0:
			code = "Hop Limit Exceeded in Transit"
		case 1:
			code = "Fragment Reassembly Time Exceeded"
		default:
			code = "Unknown"
		}
	case 4:
		mtype = "Parameter problem"
		switch i.Code {
		case 0:
			code = "Erroneous Header Field Encountered "
		case 1:
			code = "Unrecognized Next Header Type Encountered "
		case 2:
			code = "Unrecognized IPv6 Option Encountered"
		default:
			code = "Unknown"
		}
	case 128:
		mtype = "Echo Request"
		code = "Echo Request (Ping)"
	case 129:
		mtype = "Echo Reply"
		code = "Echo Reply (Ping)"
	case 130:
		mtype = "Multicast Listener Query"
		code = "Multicast Listener Query"
	case 131:
		mtype = "Multicast Listener Report"
		code = "Multicast Listener Report"
	case 132:
		mtype = "Multicast Listener Done"
		code = "Multicast Listener Done"
	case 133:
		mtype = "Router Solicitation (NDP)"
		code = "Router Solicitation (NDP)"
	case 134:
		mtype = "Router Advertisement (NDP)"
		code = "Router Advertisement (NDP)"
	case 135:
		mtype = "Neighbor Solicitation (NDP)"
		code = "Neighbor Solicitation (NDP)"
	case 136:
		mtype = "Neighbor Advertisement (NDP)"
		code = "Neighbor Advertisement (NDP)"
	case 137:
		mtype = "Redirect Message (NDP)"
		code = "Redirect Message (NDP)"
	case 138:
		mtype = "Router Renumbering"
		switch i.Code {
		case 0:
			code = "Router Renumbering Command"
		case 1:
			code = "Router Renumbering Result"
		case 255:
			code = "Sequence Number Reset"
		default:
			code = "Unknown"
		}
	case 139:
		mtype = "ICMP Node Information Query"
		switch i.Code {
		case 0:
			code = "The Data field contains an IPv6 address which is the Subject of this Query."
		case 1:
			code = "The Data field contains a name which is the Subject of this Query, or is empty, as in the case of a NOOP."
		case 2:
			code = "The Data field contains an IPv4 address which is the Subject of this Query."
		default:
			code = "Unknown"
		}
	case 140:
		mtype = "ICMP Node Information Response"
		switch i.Code {
		case 0:
			code = "A successful reply. The Reply Data field may or may not be empty."
		case 1:
			code = "The Responder refuses to supply the answer. The Reply Data field will be empty."
		case 2:
			code = "The Qtype of the Query is unknown to the Responder. The Reply Data field will be empty."
		default:
			code = "Unknown"
		}
	case 141:
		mtype = "Inverse Neighbor Discovery Solicitation Message"
		code = "Inverse Neighbor Discovery Solicitation Message"
	case 142:
		mtype = "Inverse Neighbor Discovery Advertisement Message"
		code = "Inverse Neighbor Discovery Advertisement Message"
	case 143:
		mtype = "Multicast Listener Discovery (MLDv2) reports"
		code = "Multicast Listener Discovery (MLDv2) reports"
	case 144:
		mtype = "Home Agent Address Discovery Request Message"
		code = "Home Agent Address Discovery Request Message"
	case 145:
		mtype = "Home Agent Address Discovery Reply Message"
		code = "Home Agent Address Discovery Reply Message"
	case 146:
		mtype = "Mobile Prefix Solicitation"
		code = "Mobile Prefix Solicitation"
	case 147:
		mtype = "Mobile Prefix Advertisement"
		code = "Mobile Prefix Advertisement"
	case 148:
		mtype = "Certification Path Solicitation (SEND)"
		code = "Certification Path Solicitation (SEND)"
	case 149:
		mtype = "Certification Path Advertisement (SEND)"
		code = "Certification Path Advertisement (SEND)"
	case 151:
		mtype = "Multicast Router Advertisement (MRD)"
		code = "Multicast Router Advertisement (MRD)"
	case 152:
		mtype = "Multicast Router Solicitation (MRD)"
		code = "Multicast Router Solicitation (MRD)"
	case 153:
		mtype = "Multicast Router Termination (MRD)"
		code = "Multicast Router Termination (MRD)"
	case 155:
		mtype = "RPL Control Message"
		code = "RPL Control Message"
	default:
		mtype = "Unknown"
	}
	return mtype, code
}

func (i *ICMPv6Segment) data() string {
	var data string
	switch i.Type {
	case 1, 3:
		data = fmt.Sprintf(`- Reserved: %#08x
- Data: (%d bytes) %x`,
			binary.BigEndian.Uint32(i.Data[0:4]), len(i.Data[4:]), i.Data[4:])
	case 2:
		data = fmt.Sprintf(`- MTU: %d
- Data: (%d bytes) %x`,
			binary.BigEndian.Uint32(i.Data[0:4]), len(i.Data[4:]), i.Data[4:])
	case 4:
		data = fmt.Sprintf(`- Pointer: %d
- Data: (%d bytes) %x`,
			binary.BigEndian.Uint32(i.Data[0:4]), len(i.Data[4:]), i.Data[4:])
	case 128, 129:
		data = fmt.Sprintf(`- Identifier: %d
- Sequence Number: %d
- Data: (%d bytes) %x`,
			binary.BigEndian.Uint16(i.Data[0:2]),
			binary.BigEndian.Uint16(i.Data[2:4]),
			len(i.Data[4:]), i.Data[4:])
	case 133:
		data = fmt.Sprintf(`- Reserved: %#08x
- Options: (%d bytes) %x`,
			binary.BigEndian.Uint32(i.Data[0:4]), len(i.Data[4:]), i.Data[4:])
	case 134:
		hopLimit := i.Data[0]
		flags := i.Data[1]
		managedAddress := (flags >> 7) & 1
		otherConfiguration := (flags >> 6) & 1
		reserved := flags & (1<<6 - 1)
		routerLifetime := binary.BigEndian.Uint16(i.Data[2:4])
		reachableTime := binary.BigEndian.Uint32(i.Data[4:8])
		retransTime := binary.BigEndian.Uint32(i.Data[8:12])
		options := i.Data[12:]
		data = fmt.Sprintf(`- Cur Hop Limit: %d
- Managed Address Flag: %d
- Other Configuration Flag: %d
- Reserved: %#06b
- Router Lifetime: %d
- Reachable Time: %d
- Retrans Time: %d
- Options: (%d bytes) %x`,
			hopLimit,
			managedAddress,
			otherConfiguration,
			reserved,
			routerLifetime,
			reachableTime,
			retransTime,
			len(options),
			options)
	case 135:
		address, _ := netip.AddrFromSlice(i.Data[4:20])
		data = fmt.Sprintf(`- Reserved: %#08x
- Target Address: %s
- Options: (%d bytes) %x`,
			binary.BigEndian.Uint32(i.Data[0:4]), address, len(i.Data[20:]), i.Data[20:])
	case 136:
		flags := binary.BigEndian.Uint32(i.Data[0:4])
		fromRouter := (flags >> 31) & 1
		solicited := (flags >> 30) & 1
		override := (flags >> 29) & 1
		reserved := flags & (1<<29 - 1)
		address, _ := netip.AddrFromSlice(i.Data[4:20])
		data = fmt.Sprintf(`- From Router Flag: %d
- Solicited Flag: %d
- Override Flag: %d
- Reserved: %#029b
- Target Address: %s
- Options: (%d bytes) %x`,
			fromRouter,
			solicited,
			override,
			reserved,
			address,
			len(i.Data[20:]),
			i.Data[20:])
	case 137:
		targetAddress, _ := netip.AddrFromSlice(i.Data[4:20])
		dstAddress, _ := netip.AddrFromSlice(i.Data[20:36])
		data = fmt.Sprintf(`- Reserved: %#08x
- Target Address: %s
- Destination Address: %s
- Options: (%d bytes) %x`,
			binary.BigEndian.Uint32(i.Data[0:4]),
			targetAddress,
			dstAddress,
			len(i.Data[36:]),
			i.Data[36:])
	default:
		data = fmt.Sprintf(`- Data: (%d bytes) %x`, len(i.Data), i.Data)
	}
	return data
}
