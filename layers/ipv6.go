package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"

	"github.com/shadowy-pycoder/mshark/network"
)

const HeaderSizeIPv6 = 40

func NewIPv6Proto(proto IPProto) *IPProtocol {
	return nextLayer(proto)
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
	Version          uint8         // 4 bits version field (for IPv6, this is always equal to 6).
	TrafficClass     *TrafficClass // 6 + 2 bits holds DS and ECN values.
	FlowLabel        uint32        // 20 bits high-entropy identifier of a flow of packets between a source and destination.
	PayloadLength    uint16        // 16 bits the size of the payload in octets, including any extension headers.
	NextHeader       *IPProtocol   // 8 bits specifies the type of the next header.
	UpperLayer       *IPProtocol
	FinalDestination netip.Addr
	// 8 bits replaces the time to live field in IPv4. This value is decremented by one at each forwarding node
	// and the packet is discarded if it becomes 0. However, the destination node should process the packet normally
	// even if received with a hop limit of 0.
	HopLimit   uint8
	SrcIP      netip.Addr // The unicast IPv6 address of the sending node.
	DstIP      netip.Addr // The IPv6 unicast or multicast address of the destination node(s).
	ExtHeaders []IPv6ExtHeader
	Payload    []byte // Upper-layer payload
}

func NewIPv6Packet(srcIP, dstIP netip.Addr, extHeaders []IPv6ExtHeader, upperLayer *IPProto, payload []byte) (*IPv6Packet, error) {
	if !srcIP.IsValid() || !srcIP.Is6() || !dstIP.IsValid() || !dstIP.Is6() {
		return nil, fmt.Errorf("malformed IPv6 address")
	}
	var nhdr, ul *IPProtocol
	if upperLayer != nil {
		nhdr = NewIPv6Proto(*upperLayer)
		if nhdr == nil {
			return nil, fmt.Errorf("malformed upper layer")
		}
		if slices.Contains(ExtHdrs, IPv6ExtHdrType(nhdr.Val)) {
			return nil, fmt.Errorf("cannot use extension header as upper layer")
		}
		ul = nhdr
	}
	if upperLayer == nil && len(extHeaders) == 0 {
		nhdr = IPProtocolNoNxt
	} else if len(extHeaders) > 0 {
		proto := nextHeader(IPProto(extHeaders[0].Type()))
		if proto == nil {
			return nil, fmt.Errorf("malformed extension header")
		}
		nhdr = proto
	}
	plen := len(payload)
	finalDst := dstIP
	// get final destionation from route ext header
	for _, eh := range extHeaders {
		plen += len(eh.ToBytes())
		if eh.Type() == ExtHdrRoute {
			rh := eh.(*RoutingExtHeader)
			if (rh.RoutingType == SourceRoute || rh.RoutingType == Type2RoutingHeader) && len(rh.Data) >= 20 {
				dataLen := len(rh.Data)
				addr, ok := netip.AddrFromSlice(rh.Data[dataLen-16 : dataLen])
				if ok && network.Is6(addr) {
					finalDst = addr
				}
			}
		}
	}
	if plen > 65535 {
		return nil, fmt.Errorf("maximum payload length is 65535 bytes, got %d", plen)
	}
	ipv6Packet := &IPv6Packet{
		Version:          6,
		TrafficClass:     NewTrafficClass(0),
		PayloadLength:    uint16(plen),
		NextHeader:       nhdr,
		UpperLayer:       ul,
		FinalDestination: finalDst,
		HopLimit:         255,
		SrcIP:            srcIP,
		DstIP:            dstIP,
		ExtHeaders:       extHeaders,
		Payload:          payload,
	}
	return ipv6Packet, nil
}

func (p *IPv6Packet) String() string {
	// TODO: ext headers string
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
	b := make([]byte, 4+2+1+1+16+16 /* headerSizeIPv6 */)
	binary.BigEndian.PutUint32(b[0:4], uint32(p.Version)<<28|uint32(p.TrafficClass.Raw)<<20|p.FlowLabel)
	binary.BigEndian.PutUint16(b[4:6], p.PayloadLength)
	b[6] = uint8(p.NextHeader.Val)
	b[7] = p.HopLimit
	copy(b[8:24], p.SrcIP.AsSlice())
	copy(b[24:HeaderSizeIPv6], p.DstIP.AsSlice())
	for _, eh := range p.ExtHeaders {
		b = append(b, eh.ToBytes()...)
	}
	b = append(b, p.Payload...)
	return b, nil
}

func (p *IPv6Packet) ToBytes() []byte {
	b, _ := p.MarshalBinary()
	return b
}

func (p *IPv6Packet) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderSizeIPv6 {
		return fmt.Errorf("minimum header size for IPv6 is %d bytes, got %d bytes", HeaderSizeIPv6, len(data))
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
	proto := nextHeader(IPProto(buf[6]))
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
	p.DstIP, ok = netip.AddrFromSlice(buf[24:HeaderSizeIPv6])
	if !ok {
		return fmt.Errorf("malformed IPv6 address")
	}
	// TODO: take into account ext headers
	p.Payload = buf[HeaderSizeIPv6:]
	if p.PayloadLength != 0 && int(p.PayloadLength) != len(p.Payload) { // NOTE: this condition does not always mean malformed IPv6
		return fmt.Errorf("payload length field is not equal to actual payload size")
	}
	return nil
}

// Parse parses the given byte data into an IPv6 packet struct.
func (p *IPv6Packet) Parse(data []byte) error {
	return p.UnmarshalBinary(data)
}

func nextLayer(proto IPProto) *IPProtocol {
	// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	var layer *IPProtocol
	switch proto {
	case 6:
		layer = IPProtocolTCP
	case 17:
		layer = IPProtocolUDP
	case 58:
		layer = IPProtocolICMPv6
	default:
		layer = nil
	}
	return layer
}

func (p *IPv6Packet) NextLayer() Layer {
	if next := GetLayer(LayerName(p.NextHeader.Desc)); next != nil {
		if err := next.Parse(p.Payload); err == nil {
			return next
		}
	}
	return ParseNextLayer(p.Payload, nil, nil)
}

func (p *IPv6Packet) Name() LayerName { return LayerIPv6 }

func nextHeader(proto IPProto) *IPProtocol {
	// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	var header *IPProtocol
	switch proto {
	case 0:
		header = IPProtocolHOPOPT
	case 6:
		header = IPProtocolTCP
	case 17:
		header = IPProtocolUDP
	case 43:
		header = IPProtocolRoute
	case 44:
		header = IPProtocolFragment
	case 50:
		header = IPProtocolESP
	case 51:
		header = IPProtocolAuthHeader
	case 58:
		header = IPProtocolICMPv6
	case 59:
		header = IPProtocolNoNxt
	case 60:
		header = IPProtocolOpts
	case 135:
		header = IPProtocolMobility
	case 139:
		header = IPProtocolHIP
	case 140:
		header = IPProtocolShim6
	default:
		header = nil
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
	return &IPv6PseudoHeader{SrcIP: p.SrcIP, DstIP: p.FinalDestination, UpperLayerPacketLength: uint32(len(p.Payload)), NextHeader: p.UpperLayer}
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

// NOTE: https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
// IPv6 header
// Hop-by-Hop Options header
// Destination Options header
// Routing header
// Fragment header
// Authentication header
// Encapsulating Security Payload header
// Destination Options header
// Upper-Layer header

type IPv6ExtHeader interface {
	Type() IPv6ExtHdrType
	SetNextHeader(next *IPProtocol)
	MarshalBinary() ([]byte, error)
	ToBytes() []byte
}

type IPv6ExtHdrType uint8

const (
	ExtHdrHOPOPT     IPv6ExtHdrType = 0
	ExtHdrRoute      IPv6ExtHdrType = 43
	ExtHdrFragment   IPv6ExtHdrType = 44
	ExtHdrESP        IPv6ExtHdrType = 50
	ExtHdrAuthHeader IPv6ExtHdrType = 51
	ExtHdrNoNxt      IPv6ExtHdrType = 59
	ExtHdrOpts       IPv6ExtHdrType = 60
	ExtHdrMobility   IPv6ExtHdrType = 135
	ExtHdrHIP        IPv6ExtHdrType = 139
	ExtHdrShim6      IPv6ExtHdrType = 140
)

func ExtHeaderProtoFromType(eht IPv6ExtHdrType) *IPProtocol {
	var proto *IPProtocol
	switch eht {
	case ExtHdrHOPOPT:
		proto = IPProtocolHOPOPT
	case ExtHdrRoute:
		proto = IPProtocolRoute
	case ExtHdrFragment:
		proto = IPProtocolFragment
	case ExtHdrESP:
		proto = IPProtocolESP
	case ExtHdrAuthHeader:
		proto = IPProtocolAuthHeader
	case ExtHdrNoNxt:
		proto = IPProtocolNoNxt
	case ExtHdrOpts:
		proto = IPProtocolOpts
	case ExtHdrMobility:
		proto = IPProtocolMobility
	case ExtHdrHIP:
		proto = IPProtocolHIP
	case ExtHdrShim6:
		proto = IPProtocolShim6
	default:
		proto = nil
	}
	return proto
}

var ExtHdrs = []IPv6ExtHdrType{
	ExtHdrHOPOPT,
	ExtHdrRoute,
	ExtHdrFragment,
	ExtHdrESP,
	ExtHdrAuthHeader,
	ExtHdrNoNxt,
	ExtHdrOpts,
	ExtHdrMobility,
	ExtHdrHIP,
	ExtHdrShim6,
}

type IPv6ExtHdrOptType uint8

const (
	OptPad1                            IPv6ExtHdrOptType = 0x00
	OptPadN                            IPv6ExtHdrOptType = 0x01
	OptJumboPayload                    IPv6ExtHdrOptType = 0xC2
	OptRPL                             IPv6ExtHdrOptType = 0x23
	OptRPL2                            IPv6ExtHdrOptType = 0x63
	OptTunnelEncapsulationLimit        IPv6ExtHdrOptType = 0x04
	OptRouterAlert                     IPv6ExtHdrOptType = 0x05
	OptQuickStart                      IPv6ExtHdrOptType = 0x26
	OptCALIPSO                         IPv6ExtHdrOptType = 0x07
	OptSMFDPD                          IPv6ExtHdrOptType = 0x08
	OptHomeAddress                     IPv6ExtHdrOptType = 0xC9
	OptEndpointIdentification          IPv6ExtHdrOptType = 0x8A
	OptILNPNonce                       IPv6ExtHdrOptType = 0x8B
	OptLineIdentification              IPv6ExtHdrOptType = 0x8C
	OptDeprecated                      IPv6ExtHdrOptType = 0x4D
	OptMPL                             IPv6ExtHdrOptType = 0x6D
	OptIPDFF                           IPv6ExtHdrOptType = 0xEE
	OptPerformanceandDiagnosticMetrics IPv6ExtHdrOptType = 0x0F
	OptMinimumPathMTUHopbyHop          IPv6ExtHdrOptType = 0x30
	OptIOAMDestinationandIOAMHopbyHop  IPv6ExtHdrOptType = 0x11
	OptIOAMDestinationandIOAMHopbyHop2 IPv6ExtHdrOptType = 0x31
	OptAltMark                         IPv6ExtHdrOptType = 0x12
)

type IPv6RoutingType uint8

const (
	SourceRoute          IPv6RoutingType = 0
	Nimrod               IPv6RoutingType = 1
	Type2RoutingHeader   IPv6RoutingType = 2
	RPLSourceRouteHeade  IPv6RoutingType = 3
	SegmentRoutingHeader IPv6RoutingType = 4
	CRH16                IPv6RoutingType = 5
	CRH32                IPv6RoutingType = 6
)

type TLVOpt interface {
	Type() IPv6ExtHdrOptType
	MarshalBinary() ([]byte, error)
	ToBytes() []byte
}

var _ TLVOpt = &IPv6OptPad1{}

type IPv6OptPad1 struct{}

func (pad1 *IPv6OptPad1) Type() IPv6ExtHdrOptType {
	return OptPad1
}

func (pad1 *IPv6OptPad1) MarshalBinary() ([]byte, error) {
	return []byte{0}, nil
}

func (pad1 *IPv6OptPad1) ToBytes() []byte {
	b, _ := pad1.MarshalBinary()
	return b
}

var _ TLVOpt = &IPv6OptPad1M{}

type IPv6OptPad1M struct {
	Count int // number of bytes to add
} // made up

func (pad1m *IPv6OptPad1M) Type() IPv6ExtHdrOptType {
	return OptPad1
}

func (pad1m *IPv6OptPad1M) MarshalBinary() ([]byte, error) {
	return bytes.Repeat([]byte{0}, pad1m.Count), nil
}

func (pad1m *IPv6OptPad1M) ToBytes() []byte {
	b, _ := pad1m.MarshalBinary()
	return b
}

var _ TLVOpt = &IPv6OptPadN{}

// IPv6OptPadN described in https://datatracker.ietf.org/doc/html/rfc8200#section-4.2
type IPv6OptPadN struct {
	/*
		The PadN option is used to insert two or more octets of padding
		into the Options area of a header.  For N octets of padding, the
		Opt Data Len field contains the value N-2, and the Option Data
		consists of N-2 zero-valued octets.
	*/
	OptDataLen uint8 // Length of the Option Data field of this option, in octets.
}

func (padn *IPv6OptPadN) Type() IPv6ExtHdrOptType {
	return OptPadN
}

func (padn *IPv6OptPadN) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2+padn.OptDataLen)
	b[0] = uint8(padn.Type())
	b[1] = padn.OptDataLen
	return b, nil
}

func (padn *IPv6OptPadN) ToBytes() []byte {
	b, _ := padn.MarshalBinary()
	return b
}

var _ TLVOpt = &IPv6OptHomeAddress{}

// IPv6OptHomeAddress described in https://datatracker.ietf.org/doc/html/rfc6275#section-6.3
type IPv6OptHomeAddress struct {
	// The alignment requirement for the Home Address option is 8n + 6.
	// OptDataLen uint8 /*8-bit unsigned integer.  Length of the option, in octets,
	// excluding the Option Type and Option Length fields.  This field MUST be set to 16.*/
	HomeAddress netip.Addr // The home address of the mobile node sending the packet. This address MUST be a unicast routable address.
}

func (ha *IPv6OptHomeAddress) Type() IPv6ExtHdrOptType {
	return OptHomeAddress
}

func (ha *IPv6OptHomeAddress) MarshalBinary() ([]byte, error) {
	b := make([]byte, 18)
	b[0] = uint8(ha.Type())
	b[1] = 16
	if !network.Is6(ha.HomeAddress) || !ha.HomeAddress.IsGlobalUnicast() {
		return nil, fmt.Errorf("home address should be routable unicast IPv6 address")
	}
	copy(b[2:18], ha.HomeAddress.AsSlice())
	return b, nil
}

func (ha *IPv6OptHomeAddress) ToBytes() []byte {
	b, _ := ha.MarshalBinary()
	return b
}

var _ IPv6ExtHeader = &HopByHopExtHeader{}

// HopByHopExtHeader described in https://datatracker.ietf.org/doc/html/rfc8200#section-4.3
type HopByHopExtHeader struct {
	NextHeader *IPProtocol // Identifies the type of header immediately following the Hop-by-Hop Options header.
	HdrExtLen  uint8       // Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
	Options    []TLVOpt    /* Variable-length field, of length such that the complete Hop-by-Hop Options header is an
	integer multiple of 8 octets long.  Contains one or more TLV-encoded options, as described in Section 4.2 */
}

func (hbh *HopByHopExtHeader) Type() IPv6ExtHdrType {
	return ExtHdrHOPOPT
}

func (hbh *HopByHopExtHeader) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2)
	b[0] = uint8(hbh.NextHeader.Val)
	for _, opt := range hbh.Options {
		b = append(b, opt.ToBytes()...)
	}
	b = append(b, bytes.Repeat([]byte{0}, pad8(len(b)))...)
	b[1] = uint8(len(b)/8 - 1)
	return b, nil
}

func (hbh *HopByHopExtHeader) ToBytes() []byte {
	b, _ := hbh.MarshalBinary()
	return b
}

func (hbh *HopByHopExtHeader) SetNextHeader(next *IPProtocol) {
	hbh.NextHeader = next
}

var _ IPv6ExtHeader = &RoutingExtHeader{}

func NewRouting0ExtHeader(next IPProto, addrs []netip.Addr) (*RoutingExtHeader, error) {
	for _, addr := range addrs {
		if !network.Is6(addr) {
			return nil, fmt.Errorf("addrs should be list of valid IPv6 addresses")
		}
	}
	nhdr := nextHeader(IPProto(next))
	if nhdr == nil {
		return nil, fmt.Errorf("malformed next header")
	}
	data := make([]byte, 4)
	for _, addr := range addrs {
		data = append(data, addr.AsSlice()...)
	}
	reh := &RoutingExtHeader{NextHeader: nhdr, RoutingType: SourceRoute, SegmentsLeft: uint8(len(addrs)), Data: data}
	return reh, nil
}

func NewRouting2ExtHeader(next IPProto, homeAddress netip.Addr) (*RoutingExtHeader, error) {
	if !network.Is6(homeAddress) || !homeAddress.IsGlobalUnicast() {
		return nil, fmt.Errorf("home address should be routable unicast IPv6 address")
	}
	nhdr := nextHeader(IPProto(next))
	if nhdr == nil {
		return nil, fmt.Errorf("malformed next header")
	}
	data := make([]byte, 20)
	copy(data[4:], homeAddress.AsSlice())
	reh := &RoutingExtHeader{NextHeader: nhdr, HdrExtLen: 2, RoutingType: Type2RoutingHeader, SegmentsLeft: 1, Data: data}
	return reh, nil
}

type RoutingExtHeader struct {
	NextHeader   *IPProtocol     // Identifies the type of header immediately following the Routing header.
	HdrExtLen    uint8           // Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
	RoutingType  IPv6RoutingType // identifier of a particular Routing header variant
	SegmentsLeft uint8           // Number of route segments remaining, i.e., number of explicitly listed intermediate nodes
	// still to be visited before reaching the final destination.
	Data []byte // type-specific data
}

func (rt *RoutingExtHeader) Type() IPv6ExtHdrType {
	return ExtHdrRoute
}

func (rt *RoutingExtHeader) MarshalBinary() ([]byte, error) {
	b := make([]byte, 4+len(rt.Data))
	b[0] = uint8(rt.NextHeader.Val)
	b[2] = uint8(rt.RoutingType)
	b[3] = rt.SegmentsLeft
	copy(b[4:], rt.Data)
	b = append(b, bytes.Repeat([]byte{0}, pad8(len(b)))...)
	b[1] = uint8(len(b)/8 - 1)
	return b, nil
}

func (rt *RoutingExtHeader) ToBytes() []byte {
	b, _ := rt.MarshalBinary()
	return b
}

func (rt *RoutingExtHeader) SetNextHeader(next *IPProtocol) {
	rt.NextHeader = next
}

var _ IPv6ExtHeader = &FragmentExtHeader{}

type FragmentExtHeader struct {
	NextHeader *IPProtocol // Identifies the type of header immediately following the Routing header.
	// Reserved uint8
	FragmentOffset uint16 /* 13-bit unsigned integer.  The offset, in 8-octet units, of the data following this
	header, relative to the start of the Fragmentable Part of the original packet. */
	M              bool // 1 = more fragments; 0 = last fragment.
	Identification uint32
}

func (fr *FragmentExtHeader) Type() IPv6ExtHdrType {
	return ExtHdrFragment
}

func (fr *FragmentExtHeader) MarshalBinary() ([]byte, error) {
	b := make([]byte, 8)
	b[0] = uint8(fr.NextHeader.Val)
	offset := fr.FragmentOffset << 3
	if fr.M {
		offset |= 1
	}
	binary.BigEndian.PutUint16(b[2:4], offset)
	binary.BigEndian.PutUint32(b[4:8], fr.Identification)
	return b, nil
}

func (fr *FragmentExtHeader) ToBytes() []byte {
	b, _ := fr.MarshalBinary()
	return b
}

func (fr *FragmentExtHeader) SetNextHeader(next *IPProtocol) {
	fr.NextHeader = next
}

var _ IPv6ExtHeader = &DestOptsExtHeader{}

type DestOptsExtHeader struct {
	NextHeader *IPProtocol // Identifies the type of header immediately following the Destination Options header.
	HdrExtLen  uint8       // Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
	Options    []TLVOpt    /* Variable-length field, of length such that the complete Destination Options header is an
	integer multiple of 8 octets long.  Contains one or more TLV-encoded options */
}

func (dst *DestOptsExtHeader) Type() IPv6ExtHdrType {
	return ExtHdrOpts
}

func (dst *DestOptsExtHeader) MarshalBinary() ([]byte, error) {
	if dst.HdrExtLen == 0 { // calculate length
		b := make([]byte, 2)
		b[0] = uint8(dst.NextHeader.Val)
		for _, opt := range dst.Options {
			b = append(b, opt.ToBytes()...)
		}
		b = append(b, bytes.Repeat([]byte{0}, pad8(len(b)))...)
		b[1] = uint8(len(b)/8 - 1)
		return b, nil
	}
	b := make([]byte, (int(dst.HdrExtLen)+1)*8) // max size 2048 bytes
	b[0] = uint8(dst.NextHeader.Val)
	b[1] = dst.HdrExtLen
	return b, nil
}

func (dst *DestOptsExtHeader) ToBytes() []byte {
	b, _ := dst.MarshalBinary()
	return b
}

func (dst *DestOptsExtHeader) SetNextHeader(next *IPProtocol) {
	dst.NextHeader = next
}

var _ IPv6ExtHeader = &NoNextExtHeader{}

type NoNextExtHeader struct{}

func (nn *NoNextExtHeader) Type() IPv6ExtHdrType {
	return ExtHdrNoNxt
}

func (nn *NoNextExtHeader) MarshalBinary() ([]byte, error) {
	return nil, nil
}

func (nn *NoNextExtHeader) ToBytes() []byte {
	b, _ := nn.MarshalBinary()
	return b
}

func (nn *NoNextExtHeader) SetNextHeader(next *IPProtocol) {
}

var _ IPv6ExtHeader = &MobilityExtHeader{}

type MobilityExtHeader struct {
	NextHeader *IPProtocol // Identifies the type of header immediately following the Mobility Header. Uses the same values as the IPv6 Next Header field
	HdrExtLen  uint8       // Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
	MHType     uint8       /* Identifies the particular mobility message in question. Current values are specified in Section 6.1.2 and onward.
	An unrecognized MH Type field causes an error indication to be sent. */
	// Reserved uint8
	Checksum uint16 /*
		          16-bit unsigned integer.  This field contains the checksum of the
				  Mobility Header.  The checksum is calculated from the octet string
				  consisting of a "pseudo-header" followed by the entire Mobility
				  Header starting with the Payload Proto field.  The checksum is the
				  16-bit one's complement of the one's complement sum of this
				  string.

				  The pseudo-header contains IPv6 header fields, as specified in
				  Section 8.1 of RFC 2460 [6].  The Next Header value used in the
				  pseudo-header is 135.  The addresses used in the pseudo-header are
				  the addresses that appear in the Source and Destination Address
				  fields in the IPv6 packet carrying the Mobility Header.
				  Note that the procedures of calculating upper-layer checksums
				  while away from home described in Section 11.3.1 apply even for
				  the Mobility Header.  If a mobility message has a Home Address
				  destination option, then the checksum calculation uses the home
				  address in this option as the value of the IPv6 Source Address
				  field.  The type 2 routing header is treated as explained in [6].

				  The Mobility Header is considered as the upper-layer protocol for
				  the purposes of calculating the pseudo-header.  The Upper-Layer
				  Packet Length field in the pseudo-header MUST be set to the total
				  length of the Mobility Header.

				  For computing the checksum, the checksum field is set to zero.
	*/
	MessageData []byte // A variable-length field containing the data specific to the indicated Mobility Header type.
	// Reserved uint16
	Options []TLVOpt
}

func (mb *MobilityExtHeader) Type() IPv6ExtHdrType {
	return ExtHdrMobility
}

func (mb *MobilityExtHeader) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (mb *MobilityExtHeader) ToBytes() []byte {
	b, _ := mb.MarshalBinary()
	return b
}

func (mb *MobilityExtHeader) SetNextHeader(next *IPProtocol) {
	mb.NextHeader = next
}
