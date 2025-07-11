package layers

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func openFile(path string) ([]byte, func(), error) {
	f, err := os.Open(filepath.FromSlash(fmt.Sprintf("testdata/%s.bin", path)))
	if err != nil {
		return nil, nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	return data, func() { f.Close() }, nil
}

func testPacket(t *testing.T, path string) ([]byte, func()) {
	t.Helper()
	packet, close, err := openFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return packet, close
}

func testPacketBench(b *testing.B, path string) ([]byte, func()) {
	b.Helper()
	packet, close, err := openFile(path)
	if err != nil {
		b.Fatal(err)
	}
	return packet, close
}

func BenchmarkParseARP(b *testing.B) {
	packet, close := testPacketBench(b, "arp")
	defer close()
	b.ResetTimer()
	arp := &ARPPacket{}
	for i := 0; i < b.N; i++ {
		_ = arp.Parse(packet)
		fmt.Fprint(io.Discard, arp.String())
	}
}

func TestParseARP(t *testing.T) {
	expected := &ARPPacket{
		HardwareType:     0x0001,
		ProtocolType:     0x0800,
		ProtocolTypeDesc: "IPv4",
		Hlen:             0x06,
		Plen:             0x04,
		Op:               &ARPOperation{Val: 1, Desc: "request"},
		SenderMAC:        net.HardwareAddr{0x7b, 0x13, 0x0b, 0x87, 0xea, 0x51},
		SenderIP:         netip.AddrFrom4([4]byte{0x7F, 0x00, 0x00, 0x01}),
		TargetMAC:        net.HardwareAddr{0x43, 0x40, 0x8d, 0x28, 0xca, 0x0b},
		TargetIP:         netip.AddrFrom4([4]byte{0x7F, 0x00, 0x00, 0x02}),
	}
	arp := &ARPPacket{}
	packet, close := testPacket(t, "arp")
	defer close()
	if err := arp.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, expected, arp)
}
