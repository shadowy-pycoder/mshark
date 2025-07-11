package layers

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

const headerSizeEthernet = 14

type EtherType uint16

const (
	EtherTypeIPv4 EtherType = 0x0800
	EtherTypeARP  EtherType = 0x0806
	EtherTypeIPv6 EtherType = 0x86dd
)

type EthernetType struct {
	Val  EtherType
	Desc string // Protocol description
}

func (et *EthernetType) String() string {
	return fmt.Sprintf("%s (%#04x)", et.Desc, et.Val)
}

// EthernetFrame represents Ethernet Frame
// An Ethernet frame is a data link layer protocol data unit.
type EthernetFrame struct {
	DstMAC    net.HardwareAddr // MAC address of the destination device.
	SrcMAC    net.HardwareAddr // MAC address of the source device.
	EtherType *EthernetType    // The protocol of the upper layer.
	Payload   []byte
}

func NewEthernetFrame(dstMAC, srcMAC net.HardwareAddr, et EtherType, payload []byte) (*EthernetFrame, error) {
	if len(dstMAC) != 6 || len(srcMAC) != 6 {
		return nil, fmt.Errorf("malformed hardware address")
	}
	return &EthernetFrame{
		DstMAC:    dstMAC,
		SrcMAC:    srcMAC,
		EtherType: &EthernetType{Val: et, Desc: ethertypedesc(et)},
		Payload:   payload,
	}, nil
}

func (ef *EthernetFrame) String() string {
	return fmt.Sprintf(`%s
- DstMAC: %s
- SrcMAC: %s
- EtherType: %s
- Payload: %d bytes
%s`,
		ef.Summary(),
		ef.DstMAC,
		ef.SrcMAC,
		ef.EtherType,
		len(ef.Payload),
		hex.Dump(ef.ToBytes()))
}

func (ef *EthernetFrame) Summary() string {
	return fmt.Sprintf("Ethernet Frame: Src MAC: %s -> Dst MAC: %s", ef.SrcMAC, ef.DstMAC)
}

func (ef *EthernetFrame) MarshalBinary() ([]byte, error) {
	b := make([]byte, 6+6+2+len(ef.Payload))
	copy(b[0:6], ef.DstMAC)
	copy(b[6:12], ef.SrcMAC)
	binary.BigEndian.PutUint16(b[12:14], uint16(ef.EtherType.Val))
	copy(b[14:], ef.Payload)
	return b, nil
}

func (ef *EthernetFrame) ToBytes() []byte {
	b, _ := ef.MarshalBinary()
	return b
}

func (ef *EthernetFrame) UnmarshalBinary(data []byte) error {
	if len(data) < headerSizeEthernet {
		return fmt.Errorf("did not read a complete Ethernet frame, only %d bytes read", len(data))
	}
	ef.DstMAC = net.HardwareAddr(data[0:6])
	ef.SrcMAC = net.HardwareAddr(data[6:12])
	et := EtherType(binary.BigEndian.Uint16(data[12:14]))
	etdesc := ethertypedesc(et)
	ef.EtherType = &EthernetType{Val: et, Desc: etdesc}
	ef.Payload = data[headerSizeEthernet:]
	return nil
}

// Parse parses the given byte data into an Ethernet frame.
func (ef *EthernetFrame) Parse(data []byte) error {
	return ef.UnmarshalBinary(data)
}

// NextLayer returns the name and payload of the next layer protocol based on the EtherType field of the EthernetFrame.
func (ef *EthernetFrame) NextLayer() (string, []byte) {
	return ef.EtherType.Desc, ef.Payload
}

func ethertypedesc(et EtherType) string {
	var etdesc string
	switch et {
	case EtherTypeIPv4:
		etdesc = "IPv4"
	case EtherTypeARP:
		etdesc = "ARP"
	case EtherTypeIPv6:
		etdesc = "IPv6"
	default:
		etdesc = ""
	}
	return etdesc
}
