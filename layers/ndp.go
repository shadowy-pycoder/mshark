package layers

type ICMPv6MessageType uint8

const (
	ICMPv6TypeRouterSolicitation    ICMPv6MessageType = 133
	ICMPv6TypeRouterAdvertisement   ICMPv6MessageType = 134
	ICMPv6TypeNeighborSolicitation  ICMPv6MessageType = 135
	ICMPv6TypeNeighborAdvertisement ICMPv6MessageType = 136
)

type ICMPv6Message interface {
	Type() ICMPv6MessageType
	MarshalBinary() ([]byte, error)
	ToBytes() []byte
}

var _ ICMPv6Message = &ICMPv6RouterSolicitation{}

type ICMPv6RouterSolicitation struct{}

func (rs *ICMPv6RouterSolicitation) Type() ICMPv6MessageType {
	return ICMPv6TypeRouterSolicitation
}

func (rs *ICMPv6RouterSolicitation) MarshalBinary() ([]byte, error) {
	b := make([]byte, 1)
	return b, nil
}

func (rs *ICMPv6RouterSolicitation) ToBytes() []byte {
	b, _ := rs.MarshalBinary()
	return b
}

var _ ICMPv6Message = &ICMPv6RouterAdvertisement{}

type ICMPv6RouterAdvertisement struct{}

func (ra *ICMPv6RouterAdvertisement) Type() ICMPv6MessageType {
	return ICMPv6TypeRouterAdvertisement
}

func (ra *ICMPv6RouterAdvertisement) MarshalBinary() ([]byte, error) {
	b := make([]byte, 1)
	return b, nil
}

func (ra *ICMPv6RouterAdvertisement) ToBytes() []byte {
	b, _ := ra.MarshalBinary()
	return b
}

var _ ICMPv6Message = &ICMPv6NeighborSolicitation{}

type ICMPv6NeighborSolicitation struct{}

func (ns *ICMPv6NeighborSolicitation) Type() ICMPv6MessageType {
	return ICMPv6TypeNeighborSolicitation
}

func (ns *ICMPv6NeighborSolicitation) MarshalBinary() ([]byte, error) {
	b := make([]byte, 1)
	return b, nil
}

func (ns *ICMPv6NeighborSolicitation) ToBytes() []byte {
	b, _ := ns.MarshalBinary()
	return b
}

var _ ICMPv6Message = &ICMPv6NeighborAdvertisement{}

type ICMPv6NeighborAdvertisement struct{}

func (na *ICMPv6NeighborAdvertisement) Type() ICMPv6MessageType {
	return ICMPv6TypeNeighborAdvertisement
}

func (na *ICMPv6NeighborAdvertisement) MarshalBinary() ([]byte, error) {
	b := make([]byte, 1)
	return b, nil
}

func (na *ICMPv6NeighborAdvertisement) ToBytes() []byte {
	b, _ := na.MarshalBinary()
	return b
}
