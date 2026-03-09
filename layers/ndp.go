package layers

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/shadowy-pycoder/mshark/network"
)

type ICMPv6MessageType uint8

const (
	ICMPv6TypeRouterSolicitation    ICMPv6MessageType = 133
	ICMPv6TypeRouterAdvertisement   ICMPv6MessageType = 134
	ICMPv6TypeNeighborSolicitation  ICMPv6MessageType = 135
	ICMPv6TypeNeighborAdvertisement ICMPv6MessageType = 136
)

type ICMPv6OptionType uint8

const (
	ICMPv6OptTypeSourceLLA  ICMPv6OptionType = 1
	ICMPv6OptTypeTargetLLA  ICMPv6OptionType = 2
	ICMPv6OptTypePrefixInfo ICMPv6OptionType = 3
	ICMPv6OptTypeMTU        ICMPv6OptionType = 5
	ICMPv6OptTypeRDNSS      ICMPv6OptionType = 25
)

const (
	ICMPv6OptLenLLA        int = 1 // length in 8 octets with 6 byte hardware address
	ICMPv6OptLenPrefixInfo int = 4
	ICMPv6OptLenMTU        int = 1
	ICMPv6OptLenRDNSS      int = 3
	ICMPv6RSLen            int = 8
	ICMPv6RALen            int = 16
	ICMPv6NSLen            int = 24
	ICMPv6NALen            int = 24
)

const headerChecksumOffsetICMPv6 = 42

type ICMPv6Message interface {
	Type() ICMPv6MessageType
	MarshalBinary() ([]byte, error)
	ToBytes() []byte
	SetChecksum(pseudo []byte) error
}

type ICMPv6Option interface {
	OptType() ICMPv6OptionType
	MarshalBinary() ([]byte, error)
	ToBytes() []byte
}

type LLADirection uint8

const (
	LLASource LLADirection = LLADirection(ICMPv6OptTypeSourceLLA)
	LLATarget LLADirection = LLADirection(ICMPv6OptTypeTargetLLA)
)

var _ ICMPv6Option = &ICMPv6OptLinkLayerAddress{}

// ICMPv6OptLinkLayerAddress format described in https://datatracker.ietf.org/doc/html/rfc2461#section-4.6.1
type ICMPv6OptLinkLayerAddress struct {
	Direction LLADirection
	Addr      net.HardwareAddr
}

func (lla *ICMPv6OptLinkLayerAddress) OptType() ICMPv6OptionType {
	return ICMPv6OptionType(lla.Direction)
}

func (lla *ICMPv6OptLinkLayerAddress) MarshalBinary() ([]byte, error) {
	b := make([]byte, ICMPv6OptLenLLA*8)
	if lla.Direction != LLASource && lla.Direction != LLATarget {
		return nil, fmt.Errorf("link-layer direction is not valid: %d", lla.Direction)
	}
	if len(lla.Addr) != 6 {
		return nil, fmt.Errorf("link-layer address is not valid")
	}
	b[0] = uint8(lla.OptType())
	b[1] = uint8(ICMPv6OptLenLLA)
	copy(b[2:], lla.Addr)
	return b, nil
}

func (lla *ICMPv6OptLinkLayerAddress) ToBytes() []byte {
	b, _ := lla.MarshalBinary()
	return b
}

var _ ICMPv6Option = &ICMPv6OptPrefixInfo{}

// ICMPv6OptPrefixInfo format described in https://datatracker.ietf.org/doc/html/rfc2461#section-4.6.2
type ICMPv6OptPrefixInfo struct {
	PrefixLength                   uint8 // 0-128
	OnLink                         bool
	AutonomousAddressConfiguration bool
	ValidLifetime                  uint32
	PreferredLifetime              uint32
	Prefix                         netip.Addr
}

func (pi *ICMPv6OptPrefixInfo) OptType() ICMPv6OptionType {
	return ICMPv6OptTypePrefixInfo
}

func (pi *ICMPv6OptPrefixInfo) MarshalBinary() ([]byte, error) {
	b := make([]byte, ICMPv6OptLenPrefixInfo*8)
	if !network.PrefixIsValid(pi.Prefix, int(pi.PrefixLength)) {
		return nil, fmt.Errorf("prefix information is not valid: %s/%d",
			pi.Prefix, pi.PrefixLength)
	}
	b[0] = uint8(pi.OptType())
	b[1] = uint8(ICMPv6OptLenPrefixInfo)
	b[2] = pi.PrefixLength
	if pi.OnLink {
		b[3] |= (1 << 7)
	}
	if pi.AutonomousAddressConfiguration {
		b[3] |= (1 << 6)
	}
	binary.BigEndian.PutUint32(b[4:8], pi.ValidLifetime)
	binary.BigEndian.PutUint32(b[8:12], pi.PreferredLifetime)
	// 4 bytes reserved
	copy(b[16:32], pi.Prefix.AsSlice())
	return b, nil
}

func (pi *ICMPv6OptPrefixInfo) ToBytes() []byte {
	b, _ := pi.MarshalBinary()
	return b
}

var _ ICMPv6Option = &ICMPv6OptMTU{}

// ICMPv6OptMTU format described in https://datatracker.ietf.org/doc/html/rfc2461#section-4.6.4
type ICMPv6OptMTU struct {
	MTU uint32
}

func (om *ICMPv6OptMTU) OptType() ICMPv6OptionType {
	return ICMPv6OptTypeMTU
}

func (om *ICMPv6OptMTU) MarshalBinary() ([]byte, error) {
	b := make([]byte, ICMPv6OptLenMTU*8)
	b[0] = uint8(om.OptType())
	b[1] = uint8(ICMPv6OptLenMTU)
	// 2 bytes reserved
	binary.BigEndian.PutUint32(b[4:8], om.MTU)
	return b, nil
}

func (om *ICMPv6OptMTU) ToBytes() []byte {
	b, _ := om.MarshalBinary()
	return b
}

var _ ICMPv6Option = &ICMPv6OptRDNSS{}

// ICMPv6OptRDNSS format described in https://datatracker.ietf.org/doc/html/rfc8106#section-5.1
type ICMPv6OptRDNSS struct {
	Lifetime  uint32
	Addresses []netip.Addr
}

func (rd *ICMPv6OptRDNSS) OptType() ICMPv6OptionType {
	return ICMPv6OptTypeRDNSS
}

func (rd *ICMPv6OptRDNSS) MarshalBinary() ([]byte, error) {
	b := make([]byte, (ICMPv6OptLenRDNSS-2)*8) // NOTE: -2 to account for appending the first address
	b[0] = uint8(rd.OptType())
	if len(rd.Addresses) == 0 {
		return nil, fmt.Errorf("rdnss should contain at least one IPv6 address")
	}
	b[1] = uint8(ICMPv6OptLenRDNSS - 2 + len(rd.Addresses)*2)
	// 2 bytes reserved
	binary.BigEndian.PutUint32(b[4:8], rd.Lifetime)
	for _, addr := range rd.Addresses {
		if !network.Is6(addr) {
			return nil, fmt.Errorf("rdnss address is not valid IPv6")
		}
		b = append(b, addr.AsSlice()...)
	}
	return b, nil
}

func (rd *ICMPv6OptRDNSS) ToBytes() []byte {
	b, _ := rd.MarshalBinary()
	return b
}

var _ ICMPv6Message = &ICMPv6RouterSolicitation{}

// ICMPv6RouterSolicitation format described in https://datatracker.ietf.org/doc/html/rfc2461#section-4.1
type ICMPv6RouterSolicitation struct {
	Checksum uint16
	Options  []ICMPv6Option
}

func (rs *ICMPv6RouterSolicitation) Type() ICMPv6MessageType {
	return ICMPv6TypeRouterSolicitation
}

func (rs *ICMPv6RouterSolicitation) MarshalBinary() ([]byte, error) {
	b := make([]byte, ICMPv6RSLen)
	b[0] = uint8(rs.Type())
	// b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], rs.Checksum)
	// 4 bytes reserved
	for _, opt := range rs.Options {
		ob, err := opt.MarshalBinary()
		if err != nil {
			return nil, err
		}
		b = append(b, ob...)
	}
	return b, nil
}

func (rs *ICMPv6RouterSolicitation) ToBytes() []byte {
	b, _ := rs.MarshalBinary()
	return b
}

func (rs *ICMPv6RouterSolicitation) SetChecksum(pseudo []byte) error {
	rsb, err := rs.MarshalBinary()
	if err != nil {
		return err
	}
	checksum, err := CalculateInternetChecksum(append(pseudo, rsb...), headerChecksumOffsetICMPv6)
	if err != nil {
		return err
	}
	rs.Checksum = checksum
	return nil
}

var _ ICMPv6Message = &ICMPv6RouterAdvertisement{}

type ICMPv6RouterPreference int

const (
	ICMPv6RouterPreferenceHigh     ICMPv6RouterPreference = 0b01
	ICMPv6RouterPreferenceMedium   ICMPv6RouterPreference = 0b00
	ICMPv6RouterPreferenceLow      ICMPv6RouterPreference = 0b11
	ICMPv6RouterPreferenceReserved ICMPv6RouterPreference = 0b10
)

// ICMPv6RouterAdvertisement format described in https://datatracker.ietf.org/doc/html/rfc2461#section-4.2
type ICMPv6RouterAdvertisement struct {
	Checksum             uint16
	CurHopLimit          uint8
	ManagedConfiguration bool
	OtherConfiguration   bool
	HomeAgent            bool
	Prf                  ICMPv6RouterPreference
	NDProxy              bool
	SNACRouter           bool
	RouterLifetime       uint16
	ReachableTime        uint32
	RetranstTimer        uint32
	Options              []ICMPv6Option
}

func (ra *ICMPv6RouterAdvertisement) Type() ICMPv6MessageType {
	return ICMPv6TypeRouterAdvertisement
}

func (ra *ICMPv6RouterAdvertisement) MarshalBinary() ([]byte, error) {
	b := make([]byte, ICMPv6RALen)
	b[0] = uint8(ra.Type())
	// b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], ra.Checksum)
	b[4] = ra.CurHopLimit
	if ra.ManagedConfiguration {
		b[5] |= (1 << 7)
	}
	if ra.OtherConfiguration {
		b[5] |= (1 << 6)
	}
	if ra.HomeAgent {
		b[5] |= (1 << 5)
	}
	if prf := uint8(ra.Prf); prf != 0 {
		b[5] |= (prf << 3)
	}
	if ra.NDProxy {
		b[5] |= (1 << 2)
	}
	if ra.SNACRouter {
		b[5] |= (1 << 1)
	}
	binary.BigEndian.PutUint16(b[6:8], ra.RouterLifetime)
	binary.BigEndian.PutUint32(b[8:12], ra.ReachableTime)
	binary.BigEndian.PutUint32(b[12:ICMPv6RALen], ra.RetranstTimer)
	for _, opt := range ra.Options {
		ob, err := opt.MarshalBinary()
		if err != nil {
			return nil, err
		}
		b = append(b, ob...)
	}
	return b, nil
}

func (ra *ICMPv6RouterAdvertisement) ToBytes() []byte {
	b, _ := ra.MarshalBinary()
	return b
}

func (ra *ICMPv6RouterAdvertisement) SetChecksum(pseudo []byte) error {
	rab, err := ra.MarshalBinary()
	if err != nil {
		return err
	}
	checksum, err := CalculateInternetChecksum(append(pseudo, rab...), headerChecksumOffsetICMPv6)
	if err != nil {
		return err
	}
	ra.Checksum = checksum
	return nil
}

var _ ICMPv6Message = &ICMPv6NeighborSolicitation{}

// ICMPv6NeighborSolicitation format described in https://datatracker.ietf.org/doc/html/rfc2461#section-4.3
type ICMPv6NeighborSolicitation struct {
	Checksum      uint16
	TargetAddress netip.Addr
	Options       []ICMPv6Option
}

func (ns *ICMPv6NeighborSolicitation) Type() ICMPv6MessageType {
	return ICMPv6TypeNeighborSolicitation
}

func (ns *ICMPv6NeighborSolicitation) MarshalBinary() ([]byte, error) {
	b := make([]byte, ICMPv6NSLen)
	b[0] = uint8(ns.Type())
	// b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], ns.Checksum)
	// 4 bytes reserved
	if !network.Is6(ns.TargetAddress) {
		return nil, fmt.Errorf("target address is not valid IPv6")
	}
	copy(b[8:ICMPv6NSLen], ns.TargetAddress.AsSlice())
	for _, opt := range ns.Options {
		ob, err := opt.MarshalBinary()
		if err != nil {
			return nil, err
		}
		b = append(b, ob...)
	}
	return b, nil
}

func (ns *ICMPv6NeighborSolicitation) ToBytes() []byte {
	b, _ := ns.MarshalBinary()
	return b
}

func (ns *ICMPv6NeighborSolicitation) SetChecksum(pseudo []byte) error {
	nsb, err := ns.MarshalBinary()
	if err != nil {
		return err
	}
	checksum, err := CalculateInternetChecksum(append(pseudo, nsb...), headerChecksumOffsetICMPv6)
	if err != nil {
		return err
	}
	ns.Checksum = checksum
	return nil
}

var _ ICMPv6Message = &ICMPv6NeighborAdvertisement{}

// ICMPv6NeighborAdvertisement format described in https://datatracker.ietf.org/doc/html/rfc2461#section-4.4
type ICMPv6NeighborAdvertisement struct {
	Checksum      uint16
	Router        bool
	Solicited     bool
	Override      bool
	TargetAddress netip.Addr
	Options       []ICMPv6Option
}

func (na *ICMPv6NeighborAdvertisement) Type() ICMPv6MessageType {
	return ICMPv6TypeNeighborAdvertisement
}

func (na *ICMPv6NeighborAdvertisement) MarshalBinary() ([]byte, error) {
	b := make([]byte, ICMPv6NALen)
	b[0] = uint8(na.Type())
	// b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], na.Checksum)
	if na.Router {
		b[4] |= (1 << 7)
	}
	if na.Solicited {
		b[4] |= (1 << 6)
	}
	if na.Override {
		b[4] |= (1 << 5)
	}
	// 29 bits reserved
	if !network.Is6(na.TargetAddress) {
		return nil, fmt.Errorf("target address is not valid IPv6")
	}
	copy(b[8:ICMPv6NALen], na.TargetAddress.AsSlice())
	for _, opt := range na.Options {
		ob, err := opt.MarshalBinary()
		if err != nil {
			return nil, err
		}
		b = append(b, ob...)
	}
	return b, nil
}

func (na *ICMPv6NeighborAdvertisement) ToBytes() []byte {
	b, _ := na.MarshalBinary()
	return b
}

func (na *ICMPv6NeighborAdvertisement) SetChecksum(pseudo []byte) error {
	nab, err := na.MarshalBinary()
	if err != nil {
		return err
	}
	checksum, err := CalculateInternetChecksum(append(pseudo, nab...), headerChecksumOffsetICMPv6)
	if err != nil {
		return err
	}
	na.Checksum = checksum
	return nil
}
