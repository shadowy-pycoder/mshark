package layers

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	headerSizeTLS     = 5
	HandshakeTLSVal   = 0x16 // 22
	ClientHelloTLSVal = 0x01
	ServerHelloTLSVal = 0x02
)

var TLSTooShortErr = fmt.Errorf("tls message too short")

type TLSVersion struct {
	Value uint16
	Desc  string
}

func (tv *TLSVersion) String() string {
	return fmt.Sprintf("%s (%#04x)", tv.Desc, tv.Value)
}

type Record struct {
	ContentType     uint8
	ContentTypeDesc string
	Version         *TLSVersion
	Length          uint16
	Data            []byte
}

func (r *Record) String() string {
	return fmt.Sprintf(` - Content Type: %s (%d)
 - Version: %s
 - Length: %d`,
		r.ContentTypeDesc,
		r.ContentType,
		r.Version,
		r.Length)
}

type HSTLSParser interface {
	ParseHS(data []byte) error
}

func HSTLSParserByType(hstype uint8) HSTLSParser {
	switch hstype {
	case 1:
		return &TLSClientHello{}
	case 2:
		return &TLSServerHello{}
	}
	return nil
}

type CipherSuite struct {
	Value uint16
	Desc  string
}

func (cs *CipherSuite) String() string {
	return fmt.Sprintf("%s (%#x)", cs.Desc, cs.Value)
}

type Extension struct {
	Value uint16
	Desc  string
}

func (e *Extension) String() string {
	return fmt.Sprintf("%s (%d)", e.Desc, e.Value)
}

type ServerName struct {
	Type         uint16
	Length       uint16
	SNListLength uint16
	SNType       uint8
	SNNameLength uint16
	SNName       string
}

func (sn *ServerName) Parse(data []byte) error {
	sn.Type = binary.BigEndian.Uint16(data[0:2])
	sn.Length = binary.BigEndian.Uint16(data[2:4])
	sn.SNListLength = binary.BigEndian.Uint16(data[4:6])
	sn.SNType = data[6]
	sn.SNNameLength = binary.BigEndian.Uint16(data[7:9])
	sn.SNName = string(data[9 : 9+sn.SNNameLength])
	return nil
}

func (sn *ServerName) String() string {
	return fmt.Sprintf(`server_name (len=%d) name=%s
 - Type: server_name (%d)
 - Length: %d
 - SNI List length: %d
 - SNI Type: %d
 - SNI Name Length: %d
 - SNI Name: %s`,
		sn.Length,
		sn.SNName,
		sn.Type,
		sn.Length,
		sn.SNListLength,
		sn.SNType,
		sn.SNNameLength,
		sn.SNName)
}

// https://wiki.osdev.org/TLS_Handshake#Client_Hello_Message
type TLSClientHello struct {
	Type               uint8
	TypeDesc           string
	Length             int // 3 bytes int(uint(b[2]) | uint(b[1])<<8 | uint(b[0])<<16))
	Version            *TLSVersion
	Random             []byte // 32 bytes
	SessionIDLength    uint8  // if 0 no session follows
	SessionID          string
	CipherSuitesLength uint16
	CipherSuites       []*CipherSuite
	CmprMethodsLength  uint8  // usually 0x01
	CmprMethods        []byte // usually 0x00
	ExtensionLength    uint16
	Extensions         []*Extension
	ServerName         *ServerName
	ALPN               []string
}

type TLSClientHelloRequestWrapper struct {
	Request TLSClientHelloRequest `json:"tls_request"`
}

type TLSClientHelloRequest struct {
	SNI          string   `json:"sni,omitempty"`
	Type         string   `json:"type,omitempty"`
	Version      string   `json:"version,omitempty"`
	SessionID    string   `json:"session_id,omitempty"`
	CipherSuites []string `json:"cipher_suites,omitempty"`
	Extensions   []string `json:"extensions,omitempty"`
	ALPN         []string `json:"alpn,omitempty"`
}

func (tch *TLSClientHello) MarshalJSON() ([]byte, error) {
	cs := make([]string, 0, len(tch.CipherSuites))
	for _, c := range tch.CipherSuites {
		cs = append(cs, c.String())
	}
	es := make([]string, 0, len(tch.Extensions))
	for _, e := range tch.Extensions {
		es = append(es, e.String())
	}
	var ver, sn string
	if tch.Version != nil {
		ver = tch.Version.String()
	}
	if tch.ServerName != nil {
		sn = tch.ServerName.SNName
	}
	return json.Marshal(&TLSClientHelloRequestWrapper{Request: TLSClientHelloRequest{
		SNI:          sn,
		Type:         fmt.Sprintf("%s (%d)", tch.TypeDesc, tch.Type),
		Version:      ver,
		SessionID:    tch.SessionID,
		CipherSuites: cs,
		Extensions:   es,
		ALPN:         tch.ALPN,
	}})
}

func (tch *TLSClientHello) String() string {
	return fmt.Sprintf(` - Type: %s (%d)
 - Length: %d
 - Version: %s
 - Random: %s
 - SessionIDLength: %d
 - SessionID: %s
 - CipherSuitesLength: %d
 - CipherSuites: %v
 - CmprMethodsLength: %d
 - CmprMethods: %v
 - ExtensionLength: %d
 - Extensions: %v
 - %s
 - ALPN: %v
`,
		tch.TypeDesc,
		tch.Type,
		tch.Length,
		tch.Version,
		hex.EncodeToString(tch.Random),
		tch.SessionIDLength,
		tch.SessionID,
		tch.CipherSuitesLength,
		tch.CipherSuites,
		tch.CmprMethodsLength,
		tch.CmprMethods,
		tch.ExtensionLength,
		tch.Extensions,
		tch.ServerName,
		tch.ALPN,
	)
}

func (tch *TLSClientHello) ParseHS(data []byte) error {
	// offset 7 bytes
	if len(data) < 4 {
		return fmt.Errorf("message should be at least 4 bytes, got %d bytes", len(data))
	}
	tch.Type = data[0]
	tch.TypeDesc = hstypedesc(tch.Type)
	tch.Length = int(uint(data[3]) | uint(data[2])<<8 | uint(data[1])<<16) // 6 - 8 bytes data[1:4]
	if len(data) < 6 {
		return nil
	}
	ver := binary.BigEndian.Uint16(data[4:6]) // 9 - 10 bytes data[4:6]
	tch.Version = &TLSVersion{Value: ver, Desc: verdesc(ver)}
	if len(data) < 38 {
		return nil
	}
	tch.Random = data[6:38]         // 11-42 data[6:38]
	tch.SessionIDLength = data[38]  // 43 data[38] 32 bytes
	sid := tch.SessionIDLength + 39 // 70
	if len(data) < int(sid) {
		return nil
	}
	tch.SessionID = hex.EncodeToString(data[39:sid]) // data[39:71]
	if len(data) < int(sid+2) {
		return nil
	}
	csl := binary.BigEndian.Uint16(data[sid : sid+2]) // data[71:73] suites count * 2 bytes
	tch.CipherSuitesLength = csl
	offset := uint16(sid + 2)  // 73
	cmproffset := csl + offset // 107
	css := make([]*CipherSuite, 0, csl/2)
	var i uint16
	for i < csl {
		if len(data) < int(i+offset+2) {
			return nil
		}
		val := binary.BigEndian.Uint16(data[i+offset : i+offset+2])
		valdesc := csuitedesc(val)
		css = append(css, &CipherSuite{Value: val, Desc: valdesc})
		i += 2
	}
	tch.CipherSuites = css
	if len(data) < int(cmproffset) {
		return nil
	}
	cml := data[cmproffset] // 107
	tch.CmprMethodsLength = cml
	extoffset := cmproffset + 1 + uint16(cml)
	if len(data) < int(extoffset) {
		return nil
	}
	tch.CmprMethods = data[cmproffset+1 : extoffset] // data[108:109]
	if len(data) < int(extoffset+2) {
		return nil
	}
	extlen := binary.BigEndian.Uint16(data[extoffset : extoffset+2]) // data[109:111]
	tch.ExtensionLength = extlen
	i = extoffset + 2
	exts := make([]*Extension, 0, 20)
	for i < extoffset+extlen {
		if len(data) < int(i+2) {
			return nil
		}
		typ := binary.BigEndian.Uint16(data[i : i+2])
		if len(data) < int(i+4) {
			return nil
		}
		length := binary.BigEndian.Uint16(data[i+2 : i+4])
		exts = append(exts, &Extension{Value: typ, Desc: extdesc(typ)})
		switch typ {
		case 0: // SNI
			if len(data) < int(i+length+4) {
				return nil
			}
			sn := &ServerName{}
			err := sn.Parse(data[i : i+length+4])
			if err != nil {
				return err
			}
			tch.ServerName = sn
		case 16: // ALPN
			// skip data[i+4:i+6] alpn extension length
			if len(data) < int(i+6) {
				return nil
			}
			start := i + 6
			alpns := make([]string, 0, 5)
			for start < i+length+4 {
				if len(data) < int(start) {
					return nil
				}
				alpnStringLength := data[start]
				if len(data) < int(start+uint16(alpnStringLength+1)) {
					return nil
				}
				nextProto := string(data[start+1 : start+uint16(alpnStringLength+1)])
				alpns = append(alpns, nextProto)
				start += uint16(alpnStringLength + 1)
			}
			tch.ALPN = alpns
		}
		i += length + 4
	}
	tch.Extensions = exts
	return nil
}

// https://wiki.osdev.org/TLS_Handshake#Server_Hello_Message
type TLSServerHello struct {
	Type             uint8
	TypeDesc         string
	Length           int // 3 bytes int(uint(b[2]) | uint(b[1])<<8 | uint(b[0])<<16))
	Version          *TLSVersion
	Random           []byte // 32 bytes
	SessionIDLength  uint8  // if 0 no session follows
	SessionID        string
	CipherSuite      *CipherSuite
	CmprMethod       uint8
	ExtensionLength  uint16
	Extensions       []*Extension
	SupportedVersion *TLSVersion
}

type TLSServerHelloResponseWrapper struct {
	Response TLSServerHelloResponse `json:"tls_response"`
}

type TLSServerHelloResponse struct {
	Type             string   `json:"type,omitempty"`
	Version          string   `json:"version,omitempty"`
	SessionID        string   `json:"session_id,omitempty"`
	CipherSuite      string   `json:"cipher_suite,omitempty"`
	Extensions       []string `json:"extensions,omitempty"`
	SupportedVersion string   `json:"supported_version,omitempty"`
}

func (tsh *TLSServerHello) MarshalJSON() ([]byte, error) {
	es := make([]string, 0, len(tsh.Extensions))
	for _, e := range tsh.Extensions {
		es = append(es, e.String())
	}
	var ver, supver, cs string
	if tsh.Version != nil {
		ver = tsh.Version.String()
	}
	if tsh.SupportedVersion != nil {
		supver = tsh.SupportedVersion.String()
	}
	if tsh.CipherSuite != nil {
		cs = tsh.CipherSuite.String()
	}
	return json.Marshal(&TLSServerHelloResponseWrapper{Response: TLSServerHelloResponse{
		Type:             fmt.Sprintf("%s (%d)", tsh.TypeDesc, tsh.Type),
		Version:          ver,
		SessionID:        tsh.SessionID,
		CipherSuite:      cs,
		Extensions:       es,
		SupportedVersion: supver,
	}})
}

func (tsh *TLSServerHello) String() string {
	return fmt.Sprintf(` - Type: %s (%d)
 - Length: %d
 - Version: %s
 - Random: %s
 - SessionIDLength: %d
 - SessionID: %s
 - CipherSuite: %s
 - CmprMethod: %d
 - ExtensionLength: %d
 - Extensions: %v
 - Supported Version: %s
`,
		tsh.TypeDesc,
		tsh.Type,
		tsh.Length,
		tsh.Version,
		hex.EncodeToString(tsh.Random),
		tsh.SessionIDLength,
		tsh.SessionID,
		tsh.CipherSuite,
		tsh.CmprMethod,
		tsh.ExtensionLength,
		tsh.Extensions,
		tsh.SupportedVersion,
	)
}

func (tsh *TLSServerHello) ParseHS(data []byte) error {
	// offset 7 bytes
	if len(data) < 4 {
		return fmt.Errorf("message should be at least 4 bytes, got %d bytes", len(data))
	}
	tsh.Type = data[0]
	tsh.TypeDesc = hstypedesc(tsh.Type)
	tsh.Length = int(uint(data[3]) | uint(data[2])<<8 | uint(data[1])<<16) // 6 - 8 bytes data[1:4]
	if len(data)-4 < tsh.Length {
		return fmt.Errorf("message should be at least %d bytes, got %d bytes", tsh.Length, len(data)-4)
	}
	if len(data) < 6 {
		return nil
	}
	ver := binary.BigEndian.Uint16(data[4:6]) // 9 - 10 bytes data[4:6]
	tsh.Version = &TLSVersion{Value: ver, Desc: verdesc(ver)}
	if len(data) < 38 {
		return nil
	}
	tsh.Random = data[6:38]         // 11-42 data[6:38]
	tsh.SessionIDLength = data[38]  // 43 data[38] 32 bytes
	sid := tsh.SessionIDLength + 39 // 70
	if len(data) < int(sid) {
		return nil
	}
	tsh.SessionID = hex.EncodeToString(data[39:sid]) // data[39:71]
	if len(data) < int(sid+2) {
		return nil
	}
	val := binary.BigEndian.Uint16(data[sid : sid+2])
	valdesc := csuitedesc(val)
	tsh.CipherSuite = &CipherSuite{Value: val, Desc: valdesc}
	tsh.CmprMethod = data[sid+2]
	extoffset := uint16(sid + 3)
	if len(data) < int(extoffset+2) {
		return nil
	}
	extlen := binary.BigEndian.Uint16(data[extoffset : extoffset+2])
	tsh.ExtensionLength = extlen
	exts := make([]*Extension, 0, 20)
	i := extoffset + 2
	for i < extoffset+extlen {
		if len(data) < int(i+2) {
			return nil
		}
		typ := binary.BigEndian.Uint16(data[i : i+2])
		if len(data) < int(i+4) {
			return nil
		}
		length := binary.BigEndian.Uint16(data[i+2 : i+4])
		exts = append(exts, &Extension{Value: typ, Desc: extdesc(typ)})
		switch typ {
		case 43: // supported versions
			if len(data) < int(i+6) {
				return nil
			}
			ver := binary.BigEndian.Uint16(data[i+4 : i+6])
			tsh.SupportedVersion = &TLSVersion{Value: ver, Desc: verdesc(ver)}
		}
		i += length + 4
	}
	tsh.Extensions = exts
	return nil
}

// port 443
// https://tls12.xargs.org/#client-hello/annotated
// https://tls13.xargs.org/#client-hello/annotated
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
type TLSMessage struct {
	Records []*Record
	Data    []byte
}

func (t *TLSMessage) String() string {
	return fmt.Sprintf(`%s
%s- Data: %d bytes
`, t.Summary(), t.printRecords(), len(t.Data))
}

func (t *TLSMessage) Summary() string {
	var sb strings.Builder
	sb.WriteString("TLS Message: ")
	if len(t.Records) == 0 {
		sb.WriteString(fmt.Sprintf("Ignored unknown record Len: %d", len(t.Data)))
	} else {
		for i, rec := range t.Records {
			if i > 0 {
				sb.WriteString(fmt.Sprintf("%s (%d) Len: %d ", rec.ContentTypeDesc, rec.ContentType, rec.Length))
				continue
			}
			sb.WriteString(rec.Version.String())
			sb.WriteString(" ")
			if rec.ContentType == HandshakeTLSVal {
				hstd := hstypedesc(rec.Data[0])
				sb.WriteString(fmt.Sprintf("%s ", hstd))
			}
			sb.WriteString(fmt.Sprintf("%s (%d) Len: %d ",
				rec.ContentTypeDesc,
				rec.ContentType,
				rec.Length))
			if sb.Len() > maxLenSummary {
				return sb.String()[:maxLenSummary] + string(ellipsis)
			}
		}
	}
	return sb.String()
}

func (t *TLSMessage) printRecords() string {
	var sb strings.Builder

	for _, rec := range t.Records {
		if rec.ContentType == HandshakeTLSVal {
			if rec.Data[0] == ClientHelloTLSVal {
				tc := TLSClientHello{}
				err := tc.ParseHS(rec.Data)
				if err == nil {
					sb.WriteString(fmt.Sprintf("- %s:\n", rec.ContentTypeDesc))
					sb.WriteString(tc.String())
				} else {
					sb.WriteString(fmt.Sprintf("- %s:\n%s\n", rec.ContentTypeDesc, rec))
				}
				continue
			}
			if rec.Data[0] == ServerHelloTLSVal {
				ts := TLSServerHello{}
				err := ts.ParseHS(rec.Data)
				if err == nil {
					sb.WriteString(fmt.Sprintf("- %s:\n", rec.ContentTypeDesc))
					sb.WriteString(ts.String())
				} else {
					sb.WriteString(fmt.Sprintf("- %s:\n%s\n", rec.ContentTypeDesc, rec))
				}
				continue
			}
		}
		sb.WriteString(fmt.Sprintf("- %s:\n%s\n", rec.ContentTypeDesc, rec))
	}
	return sb.String()
}

func (t *TLSMessage) Parse(data []byte) error {
	t.Records = make([]*Record, 0, 5)
	if len(data) < headerSizeTLS {
		return TLSTooShortErr
	}
	for len(data) > 0 {
		ctype := data[0]
		ctdesc := ctdesc(ctype)
		if ctdesc == "Unknown" {
			break
		}
		ver := binary.BigEndian.Uint16(data[1:3])
		verdesc := verdesc(ver)
		if verdesc == "Unknown" {
			break
		}
		rlen := binary.BigEndian.Uint16(data[3:headerSizeTLS])
		rb := uint16(headerSizeTLS + rlen)
		if rb > uint16(len(data)) {
			rb = uint16(len(data))
		}
		r := &Record{
			ContentType:     ctype,
			ContentTypeDesc: ctdesc,
			Version:         &TLSVersion{Value: ver, Desc: verdesc},
			Length:          rlen,
			Data:            data[headerSizeTLS:rb],
		}
		t.Records = append(t.Records, r)
		data = data[rb:]
	}
	t.Data = data
	return nil
}

func (t *TLSMessage) NextLayer() (layer string, payload []byte) { return }

func ctdesc(ct uint8) string {
	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
	var ctdesc string
	switch ct {
	case 20:
		ctdesc = "Change Cipher Spec"
	case 21:
		ctdesc = "Alert"
	case 22:
		ctdesc = "Handshake"
	case 23:
		ctdesc = "Application Data"
	case 24:
		ctdesc = "Heartbeat"
	case 25:
		ctdesc = "tls12_cid"
	case 26:
		ctdesc = "ACK"
	default:
		ctdesc = "Unknown"
	}
	return ctdesc
}

func verdesc(ver uint16) string {
	var verdesc string
	switch ver {
	case 0x0200:
		verdesc = "SSL 2.0"
	case 0x0300:
		verdesc = "SSL 3.0"
	case 0x0301:
		verdesc = "TLS 1.0"
	case 0x0302:
		verdesc = "TLS 1.1"
	case 0x0303:
		verdesc = "TLS 1.2"
	case 0x0304:
		verdesc = "TLS 1.3"
	default:
		verdesc = "Unknown"
	}
	return verdesc
}

func hstypedesc(hstype uint8) string {
	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
	var hstypedesc string
	switch hstype {
	case 0:
		hstypedesc = "Hello request"
	case 1:
		hstypedesc = "Client hello"
	case 2:
		hstypedesc = "Server hello"
	case 3:
		hstypedesc = "Hello verify request"
	case 4:
		hstypedesc = "New session ticket"
	case 5:
		hstypedesc = "End of early data"
	case 6:
		hstypedesc = "Hello retry request"
	case 8:
		hstypedesc = "Encrypted extensions"
	case 9:
		hstypedesc = "Request connection id"
	case 10:
		hstypedesc = "New connection id"
	case 11:
		hstypedesc = "Certificate"
	case 12:
		hstypedesc = "Server key exchange"
	case 13:
		hstypedesc = "Certificate request"
	case 14:
		hstypedesc = "Server hello done"
	case 15:
		hstypedesc = "Certificate verify"
	case 16:
		hstypedesc = "Client key exchange"
	case 17:
		hstypedesc = "Client certificate request"
	case 20:
		hstypedesc = "Finished"
	case 21:
		hstypedesc = "Certificate url"
	case 22:
		hstypedesc = "Certificate status"
	case 23:
		hstypedesc = "Supplemental data"
	case 24:
		hstypedesc = "Key update"
	case 25:
		hstypedesc = "Compressed certificate"
	case 26:
		hstypedesc = "EKT key"
	default:
		hstypedesc = "Unknown"
	}
	return hstypedesc
}

func csuitedesc(csuite uint16) string {
	var csuitedesc string
	switch csuite {
	case 0x0000:
		csuitedesc = "TLS_NULL_WITH_NULL_NULL"
	case 0x0001:
		csuitedesc = "TLS_RSA_WITH_NULL_MD5"
	case 0x0002:
		csuitedesc = "TLS_RSA_WITH_NULL_SHA"
	case 0x0003:
		csuitedesc = "TLS_RSA_EXPORT_WITH_RC4_40_MD5"
	case 0x0004:
		csuitedesc = "TLS_RSA_WITH_RC4_128_MD5"
	case 0x0005:
		csuitedesc = "TLS_RSA_WITH_RC4_128_SHA"
	case 0x0006:
		csuitedesc = "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"
	case 0x0007:
		csuitedesc = "TLS_RSA_WITH_IDEA_CBC_SHA"
	case 0x0008:
		csuitedesc = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"
	case 0x0009:
		csuitedesc = "TLS_RSA_WITH_DES_CBC_SHA"
	case 0x000A:
		csuitedesc = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0x000B:
		csuitedesc = "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"
	case 0x000C:
		csuitedesc = "TLS_DH_DSS_WITH_DES_CBC_SHA"
	case 0x000D:
		csuitedesc = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"
	case 0x000E:
		csuitedesc = "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"
	case 0x000F:
		csuitedesc = "TLS_DH_RSA_WITH_DES_CBC_SHA"
	case 0x0010:
		csuitedesc = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0x0011:
		csuitedesc = "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"
	case 0x0012:
		csuitedesc = "TLS_DHE_DSS_WITH_DES_CBC_SHA"
	case 0x0013:
		csuitedesc = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
	case 0x0014:
		csuitedesc = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"
	case 0x0015:
		csuitedesc = "TLS_DHE_RSA_WITH_DES_CBC_SHA"
	case 0x0016:
		csuitedesc = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0x0017:
		csuitedesc = "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"
	case 0x0018:
		csuitedesc = "TLS_DH_anon_WITH_RC4_128_MD5"
	case 0x0019:
		csuitedesc = "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"
	case 0x001A:
		csuitedesc = "TLS_DH_anon_WITH_DES_CBC_SHA"
	case 0x001B:
		csuitedesc = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
	case 0x001E:
		csuitedesc = "TLS_KRB5_WITH_DES_CBC_SHA"
	case 0x001F:
		csuitedesc = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"
	case 0x0020:
		csuitedesc = "TLS_KRB5_WITH_RC4_128_SHA"
	case 0x0021:
		csuitedesc = "TLS_KRB5_WITH_IDEA_CBC_SHA"
	case 0x0022:
		csuitedesc = "TLS_KRB5_WITH_DES_CBC_MD5"
	case 0x0023:
		csuitedesc = "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"
	case 0x0024:
		csuitedesc = "TLS_KRB5_WITH_RC4_128_MD5"
	case 0x0025:
		csuitedesc = "TLS_KRB5_WITH_IDEA_CBC_MD5"
	case 0x0026:
		csuitedesc = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"
	case 0x0027:
		csuitedesc = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"
	case 0x0028:
		csuitedesc = "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"
	case 0x0029:
		csuitedesc = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"
	case 0x002A:
		csuitedesc = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"
	case 0x002B:
		csuitedesc = "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"
	case 0x002C:
		csuitedesc = "TLS_PSK_WITH_NULL_SHA"
	case 0x002D:
		csuitedesc = "TLS_DHE_PSK_WITH_NULL_SHA"
	case 0x002E:
		csuitedesc = "TLS_RSA_PSK_WITH_NULL_SHA"
	case 0x002F:
		csuitedesc = "TLS_RSA_WITH_AES_128_CBC_SHA"
	case 0x0030:
		csuitedesc = "TLS_DH_DSS_WITH_AES_128_CBC_SHA"
	case 0x0031:
		csuitedesc = "TLS_DH_RSA_WITH_AES_128_CBC_SHA"
	case 0x0032:
		csuitedesc = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
	case 0x0033:
		csuitedesc = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
	case 0x0034:
		csuitedesc = "TLS_DH_anon_WITH_AES_128_CBC_SHA"
	case 0x0035:
		csuitedesc = "TLS_RSA_WITH_AES_256_CBC_SHA"
	case 0x0036:
		csuitedesc = "TLS_DH_DSS_WITH_AES_256_CBC_SHA"
	case 0x0037:
		csuitedesc = "TLS_DH_RSA_WITH_AES_256_CBC_SHA"
	case 0x0038:
		csuitedesc = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
	case 0x0039:
		csuitedesc = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
	case 0x003A:
		csuitedesc = "TLS_DH_anon_WITH_AES_256_CBC_SHA"
	case 0x003B:
		csuitedesc = "TLS_RSA_WITH_NULL_SHA256"
	case 0x003C:
		csuitedesc = "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case 0x003D:
		csuitedesc = "TLS_RSA_WITH_AES_256_CBC_SHA256"
	case 0x003E:
		csuitedesc = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"
	case 0x003F:
		csuitedesc = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"
	case 0x0040:
		csuitedesc = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
	case 0x0041:
		csuitedesc = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
	case 0x0042:
		csuitedesc = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"
	case 0x0043:
		csuitedesc = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"
	case 0x0044:
		csuitedesc = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"
	case 0x0045:
		csuitedesc = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"
	case 0x0046:
		csuitedesc = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"
	case 0x0067:
		csuitedesc = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
	case 0x0068:
		csuitedesc = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"
	case 0x0069:
		csuitedesc = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"
	case 0x006A:
		csuitedesc = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
	case 0x006B:
		csuitedesc = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
	case 0x006C:
		csuitedesc = "TLS_DH_anon_WITH_AES_128_CBC_SHA256"
	case 0x006D:
		csuitedesc = "TLS_DH_anon_WITH_AES_256_CBC_SHA256"
	case 0x0084:
		csuitedesc = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"
	case 0x0085:
		csuitedesc = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"
	case 0x0086:
		csuitedesc = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"
	case 0x0087:
		csuitedesc = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"
	case 0x0088:
		csuitedesc = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"
	case 0x0089:
		csuitedesc = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"
	case 0x008A:
		csuitedesc = "TLS_PSK_WITH_RC4_128_SHA"
	case 0x008B:
		csuitedesc = "TLS_PSK_WITH_3DES_EDE_CBC_SHA"
	case 0x008C:
		csuitedesc = "TLS_PSK_WITH_AES_128_CBC_SHA"
	case 0x008D:
		csuitedesc = "TLS_PSK_WITH_AES_256_CBC_SHA"
	case 0x008E:
		csuitedesc = "TLS_DHE_PSK_WITH_RC4_128_SHA"
	case 0x008F:
		csuitedesc = "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"
	case 0x0090:
		csuitedesc = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
	case 0x0091:
		csuitedesc = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
	case 0x0092:
		csuitedesc = "TLS_RSA_PSK_WITH_RC4_128_SHA"
	case 0x0093:
		csuitedesc = "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"
	case 0x0094:
		csuitedesc = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"
	case 0x0095:
		csuitedesc = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"
	case 0x0096:
		csuitedesc = "TLS_RSA_WITH_SEED_CBC_SHA"
	case 0x0097:
		csuitedesc = "TLS_DH_DSS_WITH_SEED_CBC_SHA"
	case 0x0098:
		csuitedesc = "TLS_DH_RSA_WITH_SEED_CBC_SHA"
	case 0x0099:
		csuitedesc = "TLS_DHE_DSS_WITH_SEED_CBC_SHA"
	case 0x009A:
		csuitedesc = "TLS_DHE_RSA_WITH_SEED_CBC_SHA"
	case 0x009B:
		csuitedesc = "TLS_DH_anon_WITH_SEED_CBC_SHA"
	case 0x009C:
		csuitedesc = "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case 0x009D:
		csuitedesc = "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case 0x009E:
		csuitedesc = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0x009F:
		csuitedesc = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
	case 0x00A0:
		csuitedesc = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"
	case 0x00A1:
		csuitedesc = "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"
	case 0x00A2:
		csuitedesc = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
	case 0x00A3:
		csuitedesc = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
	case 0x00A4:
		csuitedesc = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"
	case 0x00A5:
		csuitedesc = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"
	case 0x00A6:
		csuitedesc = "TLS_DH_anon_WITH_AES_128_GCM_SHA256"
	case 0x00A7:
		csuitedesc = "TLS_DH_anon_WITH_AES_256_GCM_SHA384"
	case 0x00A8:
		csuitedesc = "TLS_PSK_WITH_AES_128_GCM_SHA256"
	case 0x00A9:
		csuitedesc = "TLS_PSK_WITH_AES_256_GCM_SHA384"
	case 0x00AA:
		csuitedesc = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"
	case 0x00AB:
		csuitedesc = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"
	case 0x00AC:
		csuitedesc = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"
	case 0x00AD:
		csuitedesc = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"
	case 0x00AE:
		csuitedesc = "TLS_PSK_WITH_AES_128_CBC_SHA256"
	case 0x00AF:
		csuitedesc = "TLS_PSK_WITH_AES_256_CBC_SHA384"
	case 0x00B0:
		csuitedesc = "TLS_PSK_WITH_NULL_SHA256"
	case 0x00B1:
		csuitedesc = "TLS_PSK_WITH_NULL_SHA384"
	case 0x00B2:
		csuitedesc = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"
	case 0x00B3:
		csuitedesc = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"
	case 0x00B4:
		csuitedesc = "TLS_DHE_PSK_WITH_NULL_SHA256"
	case 0x00B5:
		csuitedesc = "TLS_DHE_PSK_WITH_NULL_SHA384"
	case 0x00B6:
		csuitedesc = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"
	case 0x00B7:
		csuitedesc = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"
	case 0x00B8:
		csuitedesc = "TLS_RSA_PSK_WITH_NULL_SHA256"
	case 0x00B9:
		csuitedesc = "TLS_RSA_PSK_WITH_NULL_SHA384"
	case 0x00BA:
		csuitedesc = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"
	case 0x00BB:
		csuitedesc = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"
	case 0x00BC:
		csuitedesc = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"
	case 0x00BD:
		csuitedesc = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"
	case 0x00BE:
		csuitedesc = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"
	case 0x00BF:
		csuitedesc = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"
	case 0x00C0:
		csuitedesc = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"
	case 0x00C1:
		csuitedesc = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"
	case 0x00C2:
		csuitedesc = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"
	case 0x00C3:
		csuitedesc = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"
	case 0x00C4:
		csuitedesc = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"
	case 0x00C5:
		csuitedesc = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"
	case 0x00C6:
		csuitedesc = "TLS_SM4_GCM_SM3"
	case 0x00C7:
		csuitedesc = "TLS_SM4_CCM_SM3"
	case 0x00FF:
		csuitedesc = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
	case 0x1301:
		csuitedesc = "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		csuitedesc = "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		csuitedesc = "TLS_CHACHA20_POLY1305_SHA256"
	case 0x1304:
		csuitedesc = "TLS_AES_128_CCM_SHA256"
	case 0x1305:
		csuitedesc = "TLS_AES_128_CCM_8_SHA256"
	case 0x1306:
		csuitedesc = "TLS_AEGIS_256_SHA512"
	case 0x1307:
		csuitedesc = "TLS_AEGIS_128L_SHA256"
	case 0x5600:
		csuitedesc = "TLS_FALLBACK_SCSV"
	case 0xC001:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_NULL_SHA"
	case 0xC002:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"
	case 0xC003:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"
	case 0xC004:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
	case 0xC005:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
	case 0xC006:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_NULL_SHA"
	case 0xC007:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case 0xC008:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
	case 0xC009:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case 0xC00A:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case 0xC00B:
		csuitedesc = "TLS_ECDH_RSA_WITH_NULL_SHA"
	case 0xC00C:
		csuitedesc = "TLS_ECDH_RSA_WITH_RC4_128_SHA"
	case 0xC00D:
		csuitedesc = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0xC00E:
		csuitedesc = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
	case 0xC00F:
		csuitedesc = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
	case 0xC010:
		csuitedesc = "TLS_ECDHE_RSA_WITH_NULL_SHA"
	case 0xC011:
		csuitedesc = "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case 0xC012:
		csuitedesc = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0xC013:
		csuitedesc = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case 0xC014:
		csuitedesc = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case 0xC015:
		csuitedesc = "TLS_ECDH_anon_WITH_NULL_SHA"
	case 0xC016:
		csuitedesc = "TLS_ECDH_anon_WITH_RC4_128_SHA"
	case 0xC017:
		csuitedesc = "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"
	case 0xC018:
		csuitedesc = "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"
	case 0xC019:
		csuitedesc = "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"
	case 0xC01A:
		csuitedesc = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"
	case 0xC01B:
		csuitedesc = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"
	case 0xC01C:
		csuitedesc = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"
	case 0xC01D:
		csuitedesc = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"
	case 0xC01E:
		csuitedesc = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"
	case 0xC01F:
		csuitedesc = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"
	case 0xC020:
		csuitedesc = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"
	case 0xC021:
		csuitedesc = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"
	case 0xC022:
		csuitedesc = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"
	case 0xC023:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case 0xC024:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
	case 0xC025:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
	case 0xC026:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
	case 0xC027:
		csuitedesc = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case 0xC028:
		csuitedesc = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	case 0xC029:
		csuitedesc = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
	case 0xC02A:
		csuitedesc = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
	case 0xC02B:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case 0xC02C:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case 0xC02D:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
	case 0xC02E:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
	case 0xC02F:
		csuitedesc = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0xC030:
		csuitedesc = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case 0xC031:
		csuitedesc = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
	case 0xC032:
		csuitedesc = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
	case 0xC033:
		csuitedesc = "TLS_ECDHE_PSK_WITH_RC4_128_SHA"
	case 0xC034:
		csuitedesc = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"
	case 0xC035:
		csuitedesc = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"
	case 0xC036:
		csuitedesc = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"
	case 0xC037:
		csuitedesc = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"
	case 0xC038:
		csuitedesc = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"
	case 0xC039:
		csuitedesc = "TLS_ECDHE_PSK_WITH_NULL_SHA"
	case 0xC03A:
		csuitedesc = "TLS_ECDHE_PSK_WITH_NULL_SHA256"
	case 0xC03B:
		csuitedesc = "TLS_ECDHE_PSK_WITH_NULL_SHA384"
	case 0xC03C:
		csuitedesc = "TLS_RSA_WITH_ARIA_128_CBC_SHA256"
	case 0xC03D:
		csuitedesc = "TLS_RSA_WITH_ARIA_256_CBC_SHA384"
	case 0xC03E:
		csuitedesc = "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"
	case 0xC03F:
		csuitedesc = "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"
	case 0xC040:
		csuitedesc = "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"
	case 0xC041:
		csuitedesc = "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"
	case 0xC042:
		csuitedesc = "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"
	case 0xC043:
		csuitedesc = "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"
	case 0xC044:
		csuitedesc = "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"
	case 0xC045:
		csuitedesc = "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"
	case 0xC046:
		csuitedesc = "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"
	case 0xC047:
		csuitedesc = "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"
	case 0xC048:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"
	case 0xC049:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"
	case 0xC04A:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"
	case 0xC04B:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"
	case 0xC04C:
		csuitedesc = "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"
	case 0xC04D:
		csuitedesc = "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"
	case 0xC04E:
		csuitedesc = "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"
	case 0xC04F:
		csuitedesc = "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"
	case 0xC050:
		csuitedesc = "TLS_RSA_WITH_ARIA_128_GCM_SHA256"
	case 0xC051:
		csuitedesc = "TLS_RSA_WITH_ARIA_256_GCM_SHA384"
	case 0xC052:
		csuitedesc = "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"
	case 0xC053:
		csuitedesc = "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"
	case 0xC054:
		csuitedesc = "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"
	case 0xC055:
		csuitedesc = "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"
	case 0xC056:
		csuitedesc = "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"
	case 0xC057:
		csuitedesc = "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"
	case 0xC058:
		csuitedesc = "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"
	case 0xC059:
		csuitedesc = "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"
	case 0xC05A:
		csuitedesc = "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"
	case 0xC05B:
		csuitedesc = "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"
	case 0xC05C:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"
	case 0xC05D:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"
	case 0xC05E:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"
	case 0xC05F:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"
	case 0xC060:
		csuitedesc = "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"
	case 0xC061:
		csuitedesc = "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"
	case 0xC062:
		csuitedesc = "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"
	case 0xC063:
		csuitedesc = "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"
	case 0xC064:
		csuitedesc = "TLS_PSK_WITH_ARIA_128_CBC_SHA256"
	case 0xC065:
		csuitedesc = "TLS_PSK_WITH_ARIA_256_CBC_SHA384"
	case 0xC066:
		csuitedesc = "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"
	case 0xC067:
		csuitedesc = "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"
	case 0xC068:
		csuitedesc = "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"
	case 0xC069:
		csuitedesc = "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"
	case 0xC06A:
		csuitedesc = "TLS_PSK_WITH_ARIA_128_GCM_SHA256"
	case 0xC06B:
		csuitedesc = "TLS_PSK_WITH_ARIA_256_GCM_SHA384"
	case 0xC06C:
		csuitedesc = "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"
	case 0xC06D:
		csuitedesc = "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"
	case 0xC06E:
		csuitedesc = "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"
	case 0xC06F:
		csuitedesc = "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"
	case 0xC070:
		csuitedesc = "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"
	case 0xC071:
		csuitedesc = "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"
	case 0xC072:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"
	case 0xC073:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"
	case 0xC074:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"
	case 0xC075:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"
	case 0xC076:
		csuitedesc = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"
	case 0xC077:
		csuitedesc = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"
	case 0xC078:
		csuitedesc = "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"
	case 0xC079:
		csuitedesc = "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"
	case 0xC07A:
		csuitedesc = "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC07B:
		csuitedesc = "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC07C:
		csuitedesc = "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC07D:
		csuitedesc = "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC07E:
		csuitedesc = "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC07F:
		csuitedesc = "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC080:
		csuitedesc = "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC081:
		csuitedesc = "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC082:
		csuitedesc = "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC083:
		csuitedesc = "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC084:
		csuitedesc = "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC085:
		csuitedesc = "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC086:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC087:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC088:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC089:
		csuitedesc = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC08A:
		csuitedesc = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC08B:
		csuitedesc = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC08C:
		csuitedesc = "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC08D:
		csuitedesc = "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC08E:
		csuitedesc = "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC08F:
		csuitedesc = "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC090:
		csuitedesc = "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC091:
		csuitedesc = "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC092:
		csuitedesc = "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"
	case 0xC093:
		csuitedesc = "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"
	case 0xC094:
		csuitedesc = "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"
	case 0xC095:
		csuitedesc = "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"
	case 0xC096:
		csuitedesc = "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"
	case 0xC097:
		csuitedesc = "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"
	case 0xC098:
		csuitedesc = "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"
	case 0xC099:
		csuitedesc = "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"
	case 0xC09A:
		csuitedesc = "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"
	case 0xC09B:
		csuitedesc = "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"
	case 0xC09C:
		csuitedesc = "TLS_RSA_WITH_AES_128_CCM"
	case 0xC09D:
		csuitedesc = "TLS_RSA_WITH_AES_256_CCM"
	case 0xC09E:
		csuitedesc = "TLS_DHE_RSA_WITH_AES_128_CCM"
	case 0xC09F:
		csuitedesc = "TLS_DHE_RSA_WITH_AES_256_CCM"
	case 0xC0A0:
		csuitedesc = "TLS_RSA_WITH_AES_128_CCM_8"
	case 0xC0A1:
		csuitedesc = "TLS_RSA_WITH_AES_256_CCM_8"
	case 0xC0A2:
		csuitedesc = "TLS_DHE_RSA_WITH_AES_128_CCM_8"
	case 0xC0A3:
		csuitedesc = "TLS_DHE_RSA_WITH_AES_256_CCM_8"
	case 0xC0A4:
		csuitedesc = "TLS_PSK_WITH_AES_128_CCM"
	case 0xC0A5:
		csuitedesc = "TLS_PSK_WITH_AES_256_CCM"
	case 0xC0A6:
		csuitedesc = "TLS_DHE_PSK_WITH_AES_128_CCM"
	case 0xC0A7:
		csuitedesc = "TLS_DHE_PSK_WITH_AES_256_CCM"
	case 0xC0A8:
		csuitedesc = "TLS_PSK_WITH_AES_128_CCM_8"
	case 0xC0A9:
		csuitedesc = "TLS_PSK_WITH_AES_256_CCM_8"
	case 0xC0AA:
		csuitedesc = "TLS_PSK_DHE_WITH_AES_128_CCM_8"
	case 0xC0AB:
		csuitedesc = "TLS_PSK_DHE_WITH_AES_256_CCM_8"
	case 0xC0AC:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"
	case 0xC0AD:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"
	case 0xC0AE:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"
	case 0xC0AF:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"
	case 0xC0B0:
		csuitedesc = "TLS_ECCPWD_WITH_AES_128_GCM_SHA256"
	case 0xC0B1:
		csuitedesc = "TLS_ECCPWD_WITH_AES_256_GCM_SHA384"
	case 0xC0B2:
		csuitedesc = "TLS_ECCPWD_WITH_AES_128_CCM_SHA256"
	case 0xC0B3:
		csuitedesc = "TLS_ECCPWD_WITH_AES_256_CCM_SHA384"
	case 0xC0B4:
		csuitedesc = "TLS_SHA256_SHA256"
	case 0xC0B5:
		csuitedesc = "TLS_SHA384_SHA384"
	case 0xC100:
		csuitedesc = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"
	case 0xC101:
		csuitedesc = "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"
	case 0xC102:
		csuitedesc = "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"
	case 0xC103:
		csuitedesc = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"
	case 0xC104:
		csuitedesc = "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L"
	case 0xC105:
		csuitedesc = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S"
	case 0xC106:
		csuitedesc = "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"
	case 0xCCA8:
		csuitedesc = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case 0xCCA9:
		csuitedesc = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case 0xCCAA:
		csuitedesc = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case 0xCCAB:
		csuitedesc = "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"
	case 0xCCAC:
		csuitedesc = "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"
	case 0xCCAD:
		csuitedesc = "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"
	case 0xCCAE:
		csuitedesc = "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"
	case 0xD001:
		csuitedesc = "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"
	case 0xD002:
		csuitedesc = "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"
	case 0xD003:
		csuitedesc = "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"
	case 0xD005:
		csuitedesc = "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"
	default:
		csuitedesc = "Unknown"
	}
	return csuitedesc
}

func extdesc(ext uint16) string {
	var extdesc string
	switch ext {
	case 0:
		extdesc = "server_name"
	case 1:
		extdesc = "max_fragment_length"
	case 2:
		extdesc = "client_certificate_url"
	case 3:
		extdesc = "trusted_ca_keys"
	case 4:
		extdesc = "truncated_hmac"
	case 5:
		extdesc = "status_request"
	case 6:
		extdesc = "user_mapping"
	case 7:
		extdesc = "client_authz"
	case 8:
		extdesc = "server_authz"
	case 9:
		extdesc = "cert_type"
	case 10:
		extdesc = "supported_groups"
	case 11:
		extdesc = "ec_point_formats"
	case 12:
		extdesc = "srp"
	case 13:
		extdesc = "signature_algorithms"
	case 14:
		extdesc = "use_srtp"
	case 15:
		extdesc = "heartbeat"
	case 16:
		extdesc = "application_layer_protocol_negotiation"
	case 17:
		extdesc = "status_request_v2"
	case 18:
		extdesc = "signed_certificate_timestamp"
	case 19:
		extdesc = "client_certificate_type"
	case 20:
		extdesc = "server_certificate_type"
	case 21:
		extdesc = "padding"
	case 22:
		extdesc = "encrypt_then_mac"
	case 23:
		extdesc = "extended_master_secret"
	case 24:
		extdesc = "token_binding"
	case 25:
		extdesc = "cached_info"
	case 26:
		extdesc = "tls_lts"
	case 27:
		extdesc = "compress_certificate"
	case 28:
		extdesc = "record_size_limit"
	case 29:
		extdesc = "pwd_protect"
	case 30:
		extdesc = "pwd_clear"
	case 31:
		extdesc = "password_salt"
	case 32:
		extdesc = "ticket_pinning"
	case 33:
		extdesc = "tls_cert_with_extern_psk"
	case 34:
		extdesc = "delegated_credential"
	case 35:
		extdesc = "session_ticket"
	case 36:
		extdesc = "TLMSP"
	case 37:
		extdesc = "TLMSP_proxying"
	case 38:
		extdesc = "TLMSP_delegate"
	case 39:
		extdesc = "supported_ekt_ciphers"
	case 41:
		extdesc = "pre_shared_key"
	case 42:
		extdesc = "early_data"
	case 43:
		extdesc = "supported_versions"
	case 44:
		extdesc = "cookie"
	case 45:
		extdesc = "psk_key_exchange_modes"
	case 47:
		extdesc = "certificate_authorities"
	case 48:
		extdesc = "oid_filters"
	case 49:
		extdesc = "post_handshake_auth"
	case 50:
		extdesc = "signature_algorithms_cert"
	case 51:
		extdesc = "key_share"
	case 52:
		extdesc = "transparency_info"
	case 53:
		extdesc = "connection_id (deprecated)"
	case 54:
		extdesc = "connection_id"
	case 55:
		extdesc = "external_id_hash"
	case 56:
		extdesc = "external_session_id"
	case 57:
		extdesc = "quic_transport_parameters"
	case 58:
		extdesc = "ticket_request"
	case 59:
		extdesc = "dnssec_chain"
	case 60:
		extdesc = "sequence_number_encryption_algorithms"
	case 61:
		extdesc = "rrc"
	case 62:
		extdesc = "tls_flags"
	case 64768:
		extdesc = "ech_outer_extensions"
	case 65037:
		extdesc = "encrypted_client_hello"
	case 65281:
		extdesc = "renegotiation_info"
	default:
		extdesc = "Unknown"
	}
	return extdesc
}
