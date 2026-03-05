package layers

import (
	"fmt"
	"io"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkParseIPv6(b *testing.B) {
	packet, close := testPacketBench(b, "ipv6")
	defer close()
	b.ResetTimer()
	ip := &IPv6Packet{}
	for b.Loop() {
		_ = ip.Parse(packet)
		fmt.Fprint(io.Discard, ip.String())
	}
}

func TestParseIPv6(t *testing.T) {
	expected := &IPv6Packet{
		Version:       6,
		TrafficClass:  &TrafficClass{Raw: 0, DSCP: 0, DSCPDesc: "Standard (DF)", ECN: 0},
		FlowLabel:     455085,
		PayloadLength: 40,
		NextHeader:    NewIPv6Proto(ProtoTCP),
		HopLimit:      64,
		SrcIP: netip.AddrFrom16([16]byte{
			0xFD, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xF2, 0x3F, 0xD1, 0x59, 0x50, 0x48, 0x9C, 0x14,
		}),
		DstIP: netip.AddrFrom16([16]byte{
			0x26, 0x20, 0x00, 0x2D, 0x40, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2B,
		}),
		Payload: []byte{},
	}
	ip := &IPv6Packet{}
	packet, close := testPacket(t, "ipv6")
	defer close()
	if err := ip.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, expected, ip)
}
