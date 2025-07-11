package layers

import (
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkParseEthernet(b *testing.B) {
	packet, close := testPacketBench(b, "ethernet")
	defer close()
	b.ResetTimer()
	eth := &EthernetFrame{}
	for i := 0; i < b.N; i++ {
		_ = eth.Parse(packet)
		fmt.Fprint(io.Discard, eth.String())
	}
}

func TestParseEthernet(t *testing.T) {
	expected := &EthernetFrame{
		DstMAC:    net.HardwareAddr{0x7b, 0x13, 0x0b, 0x87, 0xea, 0x51},
		SrcMAC:    net.HardwareAddr{0x43, 0x40, 0x8d, 0x28, 0xca, 0x0b},
		EtherType: &EthernetType{Val: 0x0800, Desc: "IPv4"},
		Payload:   []byte{},
		DstVendor: net.HardwareAddr{0x7b, 0x13, 0x0b, 0x87, 0xea, 0x51}.String(),
		SrcVendor: net.HardwareAddr{0x43, 0x40, 0x8d, 0x28, 0xca, 0x0b}.String(),
	}
	eth := &EthernetFrame{}
	packet, close := testPacket(t, "ethernet")
	defer close()
	if err := eth.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, expected, eth)
}
