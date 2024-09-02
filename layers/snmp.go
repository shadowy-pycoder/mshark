package layers

import "fmt"

// https://www.ranecommercial.com/legacy/pdf/ranenotes/SNMP_Simple_Network_Management_Protocol.pdf
// https://wiki.wireshark.org/SNMP
// port 161, 162
type SNMPMessage struct{}

func (s *SNMPMessage) String() string {
	return fmt.Sprintf(`%s`, s.Summary())
}

func (s *SNMPMessage) Summary() string {
	return fmt.Sprint("SNMP Message:")
}

func (s *SNMPMessage) Parse(data []byte) error {
	return nil
}

func (s *SNMPMessage) NextLayer() (string, []byte) {
	return "", nil
}
