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
	s.Payload = buf
	return nil
}

func (s *SNMPMessage) NextLayer() Layer { return nil }
func (s *SNMPMessage) Name() string     { return "SNMP" }
