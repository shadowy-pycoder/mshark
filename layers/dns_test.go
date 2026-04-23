package layers

import (
	"fmt"
	"io"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkParseDNS(b *testing.B) {
	packet, close := testPacketBench(b, "dns")
	defer close()
	b.ResetTimer()
	dns := &DNSMessage{}
	for b.Loop() {
		_ = dns.Parse(packet)
		fmt.Fprint(io.Discard, dns.String())
	}
}

func TestParseDNS(t *testing.T) {
	expected := &DNSMessage{
		TransactionID: 63448,
		Flags: &DNSFlags{
			Raw:    33152,
			QR:     DNSReply,
			OPCode: DNSOpCodeQuery,
			AA:     0,
			TC:     0,
			RD:     1,
			RA:     1,
			Z:      0,
			AU:     0,
			NA:     0,
			RCode:  DNSRCodeNoError,
		},
		QDCount: 1,
		ANCount: 7,
		NSCount: 4,
		ARCount: 9,
		Questions: []*QueryEntry{
			{
				Name: "www.googleapis.com",
				Type: &RecordType{
					Name: "A",
					Val:  1,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
			},
		},
		AnswerRRs: []*ResourceRecord{
			{
				Name: "www.googleapis.com",
				Type: &RecordType{
					Name: "A",
					Val:  1,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      280,
				RDLength: 4,
				RData: &RDataA{
					Address: netip.AddrFrom4([4]byte{0x8e, 0xfa, 0x4a, 0x4a}),
				},
			},
			{
				Name: "www.googleapis.com",
				Type: &RecordType{
					Name: "A",
					Val:  1,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      280,
				RDLength: 4,
				RData: &RDataA{
					Address: netip.AddrFrom4([4]byte{0xac, 0xd9, 0x15, 0xaa}),
				},
			},
			{
				Name: "www.googleapis.com",
				Type: &RecordType{
					Name: "A",
					Val:  1,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      280,
				RDLength: 4,
				RData: &RDataA{
					Address: netip.AddrFrom4([4]byte{0x8e, 0xfa, 0x4a, 0x6a}),
				},
			},
			{
				Name: "www.googleapis.com",
				Type: &RecordType{
					Name: "A",
					Val:  1,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      280,
				RDLength: 4,
				RData: &RDataA{
					Address: netip.AddrFrom4([4]byte{0xd8, 0x3a, 0xcf, 0xca}),
				},
			},
			{
				Name: "www.googleapis.com",
				Type: &RecordType{
					Name: "A",
					Val:  1,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      280,
				RDLength: 4,
				RData: &RDataA{
					Address: netip.AddrFrom4([4]byte{0x8e, 0xfa, 0x4a, 0x2a}),
				},
			},
			{
				Name: "www.googleapis.com",
				Type: &RecordType{
					Name: "A",
					Val:  1,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      280,
				RDLength: 4,
				RData: &RDataA{
					Address: netip.AddrFrom4([4]byte{0x8e, 0xfa, 0x4a, 0xaa}),
				},
			},
			{
				Name: "www.googleapis.com",
				Type: &RecordType{
					Name: "A",
					Val:  1,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      280,
				RDLength: 4,
				RData: &RDataA{
					Address: netip.AddrFrom4([4]byte{0x8e, 0xfa, 0x4a, 0x8a}),
				},
			},
		},
		AuthorityRRs: []*ResourceRecord{
			{
				Name: "googleapis.com",
				Type: &RecordType{
					Name: "NS",
					Val:  2,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      89935,
				RDLength: 13,
				RData: &RDataNS{
					NsdName: "ns2.google.com",
				},
			},
			{
				Name: "googleapis.com",
				Type: &RecordType{
					Name: "NS",
					Val:  2,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      89935,
				RDLength: 6,
				RData: &RDataNS{
					NsdName: "ns4.google.com",
				},
			},
			{
				Name: "googleapis.com",
				Type: &RecordType{
					Name: "NS",
					Val:  2,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      89935,
				RDLength: 6,
				RData: &RDataNS{
					NsdName: "ns1.google.com",
				},
			},
			{
				Name: "googleapis.com",
				Type: &RecordType{
					Name: "NS",
					Val:  2,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      89935,
				RDLength: 6,
				RData: &RDataNS{
					NsdName: "ns3.google.com",
				},
			},
		},
		AdditionalRRs: []*ResourceRecord{
			{
				Name: "ns2.google.com",
				Type: &RecordType{
					Name: "A",
					Val:  1,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      89935,
				RDLength: 4,
				RData: &RDataA{
					Address: netip.AddrFrom4([4]byte{0xd8, 0xef, 0x22, 0x0a}),
				},
			},
			{
				Name: "ns1.google.com",
				Type: &RecordType{
					Name: "A",
					Val:  1,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      266086,
				RDLength: 4,
				RData: &RDataA{
					Address: netip.AddrFrom4([4]byte{0xd8, 0xef, 0x20, 0x0a}),
				},
			},
			{
				Name: "ns3.google.com",
				Type: &RecordType{
					Name: "A",
					Val:  1,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      89935,
				RDLength: 4,
				RData: &RDataA{
					Address: netip.AddrFrom4([4]byte{0xd8, 0xef, 0x24, 0x0a}),
				},
			},
			{
				Name: "ns4.google.com",
				Type: &RecordType{
					Name: "A",
					Val:  1,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      89935,
				RDLength: 4,
				RData: &RDataA{
					Address: netip.AddrFrom4([4]byte{0xd8, 0xef, 0x26, 0x0a}),
				},
			},
			{
				Name: "ns2.google.com",
				Type: &RecordType{
					Name: "AAAA",
					Val:  28,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      89935,
				RDLength: 16,
				RData: &RDataAAAA{
					Address: netip.AddrFrom16([16]byte{
						0x20, 0x01, 0x48, 0x60, 0x48, 0x02, 0x00, 0x34,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
					}),
				},
			},
			{
				Name: "ns1.google.com",
				Type: &RecordType{
					Name: "AAAA",
					Val:  28,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      89935,
				RDLength: 16,
				RData: &RDataAAAA{
					Address: netip.AddrFrom16([16]byte{
						0x20, 0x01, 0x48, 0x60, 0x48, 0x02, 0x00, 0x32,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
					}),
				},
			},
			{
				Name: "ns3.google.com",
				Type: &RecordType{
					Name: "AAAA",
					Val:  28,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      89935,
				RDLength: 16,
				RData: &RDataAAAA{
					Address: netip.AddrFrom16([16]byte{
						0x20, 0x01, 0x48, 0x60, 0x48, 0x02, 0x00, 0x36,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
					}),
				},
			},
			{
				Name: "ns4.google.com",
				Type: &RecordType{
					Name: "AAAA",
					Val:  28,
				},
				Class: &RecordClass{
					Name: "IN",
					Val:  1,
				},
				TTL:      89935,
				RDLength: 16,
				RData: &RDataAAAA{
					Address: netip.AddrFrom16([16]byte{
						0x20, 0x01, 0x48, 0x60, 0x48, 0x02, 0x00, 0x38,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
					}),
				},
			},
			{
				Name: "Root",
				Type: &RecordType{
					Name: "OPT",
					Val:  41,
				},
				Class: &RecordClass{},
				RData: &RDataOPT{
					UDPPayloadSize:     1232,
					HigherBitsExtRCode: 0,
					EDNSVer:            0,
					Z:                  0,
					DataLen:            0,
				},
			},
		},
	}
	dns := &DNSMessage{}
	packet, close := testPacket(t, "dns")
	defer close()
	if err := dns.Parse(packet); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, expected, dns)
}
