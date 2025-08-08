package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const messageSizeSSH = 6

var protoSSH = []byte("SSH-")

type Message struct {
	PacketLength     uint32
	PaddingLength    uint8
	MesssageType     uint8
	MesssageTypeDesc string
	Payload          []byte
}

func (m *Message) String() string {
	if m.PacketLength == 0 {
		return fmt.Sprintf(`- Payload: %d bytes`, len(m.Payload))
	}
	return fmt.Sprintf(` - Packet Length: %d
 - Padding Length: %d
 - Message Type: %s (%d)
 - Payload: %d bytes`,
		m.PacketLength,
		m.PaddingLength,
		m.MesssageTypeDesc,
		m.MesssageType,
		len(m.Payload))
}

type SSHMessage struct {
	Protocol string
	Messages []*Message
}

func (s *SSHMessage) String() string {
	return fmt.Sprintf(`%s
%s
`, s.Summary(), s.printMessages())
}

func (s *SSHMessage) Summary() string {
	var sb strings.Builder
	sb.WriteString("SSH Message: ")
	if s.Protocol != "" {
		sb.WriteString(s.Protocol)
		return sb.String()
	}
	if len(s.Messages) == 1 && s.Messages[0].PacketLength == 0 {
		sb.WriteString(fmt.Sprintf("Encrypted or partial data Len: %d", len(s.Messages[0].Payload)))
		return sb.String()
	}
	for _, message := range s.Messages {
		if message.PacketLength != 0 {
			sb.WriteString(fmt.Sprintf("%s (%d) Len: %d ",
				message.MesssageTypeDesc,
				message.MesssageType,
				message.PacketLength))
		}
		if sb.Len() > maxLenSummary {
			return sb.String()[:maxLenSummary] + string(ellipsis)
		}
	}
	return sb.String()
}

func (s *SSHMessage) printMessages() string {
	var sb strings.Builder

	for _, message := range s.Messages {
		if message.MesssageTypeDesc == "" {
			sb.WriteString(fmt.Sprintf("%s\n", message))
		} else {
			sb.WriteString(fmt.Sprintf("- %s:\n%s\n", message.MesssageTypeDesc, message))
		}
	}
	return sb.String()
}

func (s *SSHMessage) Parse(data []byte) error {
	if len(data) < messageSizeSSH {
		return fmt.Errorf("minimum message size for SSH is %d bytes, got %d bytes", messageSizeSSH, len(data))
	}
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	if bytes.HasSuffix(buf, crlf) {
		p := bytes.TrimSuffix(buf, crlf)
		if !bytes.Contains(p, protoSSH) {
			return fmt.Errorf("message should contain SSH-")
		}
		s.Protocol = bytesToStr(p)
		return nil
	}
	s.Messages = make([]*Message, 0, 3)
	for len(buf) > 0 {
		if len(buf) < 4 {
			return ErrSliceBounds
		}
		m := &Message{}
		s.Messages = append(s.Messages, m)
		plen := binary.BigEndian.Uint32(buf[0:4])
		if plen > 0xffff {
			m.Payload = buf
			break
		}
		if len(buf) < 5 {
			return ErrSliceBounds
		}
		m.MesssageType = buf[5]
		if m.MesssageTypeDesc = mtypedesc(m.MesssageType); m.MesssageTypeDesc == "Unknown" {
			m.Payload = buf
			break
		}
		m.PacketLength = plen
		m.PaddingLength = buf[4]
		offset := int(messageSizeSSH + m.PacketLength - 2)
		if offset <= len(buf) {
			m.Payload = buf[messageSizeSSH:offset]
			buf = buf[offset:]
		} else {
			m.Payload = buf[messageSizeSSH:]
			break
		}
	}
	return nil
}

func (s *SSHMessage) NextLayer() Layer { return nil }
func (s *SSHMessage) Name() string     { return "SSH" }

// https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml
func mtypedesc(mtype uint8) string {
	var mtypedesc string
	switch mtype {
	case 20:
		mtypedesc = "Key Exchange Init"
	case 21:
		mtypedesc = "New Keys"
	case 30:
		mtypedesc = "Elliptic Curve Diffie-Hellman Key Exchange Init"
	case 31:
		mtypedesc = "Elliptic Curve Diffie-Hellman Key Exchange Reply"
	default:
		mtypedesc = "Unknown"
	}
	return mtypedesc
}
