package layers

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkParseTCP(b *testing.B) {
	packet, close := testPacketBench(b, "tcp")
	defer close()
	b.ResetTimer()
	tcp := &TCPSegment{}
	for i := 0; i < b.N; i++ {
		_ = tcp.Parse(packet)
		fmt.Fprint(io.Discard, tcp.String())
	}
}

func TestParseTCP(t *testing.T) {
	expected := &TCPSegment{
		SrcPort:    42776,
		DstPort:    443,
		SeqNumber:  2726715057,
		AckNumber:  0,
		DataOffset: 10,
		Reserved:   0,
		Flags: &TCPFlags{
			Raw: 2,
			Val: []*TCPFlag{
				{Val: 0, Desc: "CWR"},
				{Val: 0, Desc: "ECE"},
				{Val: 0, Desc: "URG"},
				{Val: 0, Desc: "ACK"},
				{Val: 0, Desc: "PSH"},
				{Val: 0, Desc: "RST"},
				{Val: 1, Desc: "SYN"},
				{Val: 0, Desc: "FIN"},
			},
		},
		WindowSize: 64240,
		Checksum:   30263,
		Options: []byte{
			0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xac, 0xf8,
			0x48, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
		},
		Payload: []byte{},
	}
	tcp := &TCPSegment{}
	packet, close := testPacket(t, "tcp")
	defer close()
	if err := tcp.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, expected, tcp)
}
