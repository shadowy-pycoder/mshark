package layers

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkParseUDP(b *testing.B) {
	packet, close := testPacketBench(b, "udp")
	defer close()
	b.ResetTimer()
	udp := &UDPSegment{}
	for i := 0; i < b.N; i++ {
		_ = udp.Parse(packet)
		fmt.Fprint(io.Discard, udp.String())
	}
}

func TestParseUDP(t *testing.T) {
	expected := &UDPSegment{
		SrcPort:   33168,
		DstPort:   53,
		UDPLength: 52,
		Checksum:  3985,
		Payload: []byte{
			0xa8, 0x24, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x03, 0x77, 0x77, 0x77, 0x07, 0x67, 0x73, 0x74, 0x61, 0x74,
			0x69, 0x63, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x41, 0x00, 0x01,
			0x00, 0x00, 0x29, 0x05, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
	}
	udp := &UDPSegment{}
	packet, close := testPacket(t, "udp")
	defer close()
	if err := udp.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, expected, udp)
}
