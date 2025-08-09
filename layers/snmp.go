package layers

import "fmt"

// https://www.ranecommercial.com/legacy/pdf/ranenotes/SNMP_Simple_Network_Management_Protocol.pdf
// https://wiki.wireshark.org/SNMP
// port 161, 162
type SNMPMessage struct {
	Payload []byte
}

func (s *SNMPMessage) String() string {
	return s.Summary()
}

func (s *SNMPMessage) Summary() string {
	return fmt.Sprintf("SNMP Message: %d bytes", len(s.Payload))
}

func (s *SNMPMessage) Parse(data []byte) error {
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	if !checkSNMP(buf) {
		return fmt.Errorf("not ASN.1 SEQUENCE")
	}
	s.Payload = buf
	return nil
}

func (s *SNMPMessage) NextLayer() Layer { return nil }
func (s *SNMPMessage) Name() LayerName  { return LayerSNMP }

func checkSNMP(data []byte) bool {
	return len(data) > 6 && data[0] == 0x30 && (data[2] == 0x02 || data[2] == 0x04)
}
