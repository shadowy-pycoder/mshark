package mshark

import (
	"io"
	"testing"

	"github.com/shadowy-pycoder/mshark/network"
)

func BenchmarkOpenLive(b *testing.B) {
	b.ResetTimer()
	in, err := network.InterfaceByName("any")
	if err != nil {
		b.Fatal(err)
	}
	conf := Config{
		Device:      in,
		Snaplen:     1600,
		PacketCount: b.N,
	}
	pw := NewWriter(io.Discard, false)
	if err := OpenLive(&conf, pw); err != nil {
		b.Fatal(err)
	}
}
