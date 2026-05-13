package layers

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

const headerSizeDNS = 12

type OpCode uint8

const (
	OpCodeQuery    OpCode = 0
	OpCodeInvQuery OpCode = 1
	OpCodeStatus   OpCode = 2
	OpCodeNotify   OpCode = 4
	OpCodeUpdate   OpCode = 5
	OpCodeDSO      OpCode = 6
)

type DNSOpCode struct {
	Val  OpCode `json:"val"`
	Desc string `json:"desc"`
}

func (do *DNSOpCode) String() string {
	return fmt.Sprintf("%s (%d)", do.Desc, do.Val)
}

func NewDNSOpCode(opcode OpCode) *DNSOpCode {
	return getopcode(opcode)
}

var (
	DNSOpCodeQuery    *DNSOpCode = &DNSOpCode{Val: OpCodeQuery, Desc: "Standard query"}
	DNSOpCodeInvQuery *DNSOpCode = &DNSOpCode{Val: OpCodeInvQuery, Desc: "Inverse query"}
	DNSOpCodeStatus   *DNSOpCode = &DNSOpCode{Val: OpCodeStatus, Desc: "Server status request"}
	DNSOpCodeNotify   *DNSOpCode = &DNSOpCode{Val: OpCodeNotify, Desc: "Notify"}
	DNSOpCodeUpdate   *DNSOpCode = &DNSOpCode{Val: OpCodeUpdate, Desc: "Update"}
	DNSOpCodeDSO      *DNSOpCode = &DNSOpCode{Val: OpCodeDSO, Desc: "Stateful operation"}
)

type QRFlag uint8

const (
	QRFlagQuery QRFlag = 0
	QRFlagReply QRFlag = 1
)

type DNSQRFlag struct {
	Val  QRFlag `json:"val"`
	Desc string `json:"desc"`
}

var (
	DNSQuery *DNSQRFlag = &DNSQRFlag{Val: QRFlagQuery, Desc: "query"}
	DNSReply *DNSQRFlag = &DNSQRFlag{Val: QRFlagReply, Desc: "reply"}
)

func (qr *DNSQRFlag) String() string {
	return fmt.Sprintf("%s (%d)", qr.Desc, qr.Val)
}

func NewDNSQRFlag(qr QRFlag) *DNSQRFlag {
	return qrdesc(qr)
}

type RCode uint8

const (
	RCodeNoError     RCode = 0
	RCodeFormatError RCode = 1
	RCodeServerFail  RCode = 2
	RCodeNameError   RCode = 3
	RCodeNotImpl     RCode = 4
	RCodeRefused     RCode = 5
	RCodeYXDomain    RCode = 6
	RCodeYXRRSet     RCode = 7
	RCodeNXRRSet     RCode = 8
	RCodeNotAuth     RCode = 9
	RCodeNotZone     RCode = 10
	RCodeDSOTypeNI   RCode = 11
	RCodeBadVers     RCode = 16
	RCodeBadKey      RCode = 17
	RCodeBadTime     RCode = 18
	RCodeBadMode     RCode = 19
	RCodeBadName     RCode = 20
	RCodeBadAlg      RCode = 21
	RCodeBadTrunc    RCode = 22
	RCodeBadCookie   RCode = 23
)

type DNSRCode struct {
	Val  RCode  `json:"val"`
	Desc string `json:"desc"`
}

var (
	DNSRCodeNoError   = &DNSRCode{Val: RCodeNoError, Desc: "No error"}
	DNSRCodeFormatErr = &DNSRCode{Val: RCodeFormatError, Desc: "Format error"}
	DNSRCodeServFail  = &DNSRCode{Val: RCodeServerFail, Desc: "Server failed to complete the DNS request"}
	DNSRCodeNXDomain  = &DNSRCode{Val: RCodeNameError, Desc: "Domain name does not exist"}
	DNSRCodeNotImpl   = &DNSRCode{Val: RCodeNotImpl, Desc: "Function not implemented"}
	DNSRCodeRefused   = &DNSRCode{Val: RCodeRefused, Desc: "The server refused to answer for the query"}
	DNSRCodeYXDomain  = &DNSRCode{Val: RCodeYXDomain, Desc: "Name that should not exist, does exist"}
	DNSRCodeYXRRSet   = &DNSRCode{Val: RCodeYXRRSet, Desc: "RRset that should not exist, does exist"}
	DNSRCodeNXRRSet   = &DNSRCode{Val: RCodeNXRRSet, Desc: "Server not authoritative for the zone"}
	DNSRCodeNotAuth   = &DNSRCode{Val: RCodeNotAuth, Desc: "Server Not Authoritative for zone"}
	DNSRCodeNotZone   = &DNSRCode{Val: RCodeNotZone, Desc: "Name not contained in zone"}
	DNSRCodeDSOTypeNI = &DNSRCode{Val: RCodeDSOTypeNI, Desc: "DSO-TYPE Not Implemented"}
	DNSRCodeBadVers   = &DNSRCode{Val: RCodeBadVers, Desc: "Bad OPT Version/TSIG Signature Failure"}
	DNSRCodeBadKey    = &DNSRCode{Val: RCodeBadKey, Desc: "Key not recognized"}
	DNSRCodeBadTime   = &DNSRCode{Val: RCodeBadTime, Desc: "Signature out of time window"}
	DNSRCodeBadMode   = &DNSRCode{Val: RCodeBadMode, Desc: "Bad TKEY Mode"}
	DNSRCodeBadName   = &DNSRCode{Val: RCodeBadName, Desc: "Duplicate key name"}
	DNSRCodeBadAlg    = &DNSRCode{Val: RCodeBadAlg, Desc: "Algorithm not supported"}
	DNSRCodeBadTrunc  = &DNSRCode{Val: RCodeBadTrunc, Desc: "Bad Truncation"}
	DNSRCodeBadCookie = &DNSRCode{Val: RCodeBadCookie, Desc: "Bad/missing Server Cookie"}
)

func (rc *DNSRCode) String() string {
	return fmt.Sprintf("%s (%d)", rc.Desc, rc.Val)
}

func NewDNSRCode(rc RCode) *DNSRCode {
	return rcdesc(rc)
}

type DNSFlags struct {
	Raw    uint16     `json:"raw"`
	QR     *DNSQRFlag `json:"qr"`     // Indicates if the message is a query (0) or a reply (1).
	OPCode *DNSOpCode `json:"opcode"` // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
	AA     uint8      `json:"aa"`     // Authoritative Answer, in a response, indicates if the DNS server is authoritative for the queried hostname.
	TC     uint8      `json:"tc"`     // TrunCation, indicates that this message was truncated due to excessive length.
	RD     uint8      `json:"rd"`     // Recursion Desired, indicates if the client means a recursive query.
	RA     uint8      `json:"ra"`     // Recursion Available, in a response, indicates if the replying DNS server supports recursion.
	Z      uint8      `json:"z"`      // Zero, reserved for future use.
	AU     uint8      `json:"au"`     // Indicates if answer/authority portion was authenticated by the server.
	NA     uint8      `json:"na"`     // Indicates if non-authenticated data is accepatable.
	RCode  *DNSRCode  `json:"rcode"`  // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
}

func (df *DNSFlags) String() string {
	var flags string
	switch df.QR {
	case DNSQuery:
		flags = fmt.Sprintf(`  - Response: Message is a %s
  - Opcode: %s
  - Truncated: %d
  - Recursion desired: %d
  - Reserved: %d
  - Non-authenticated data: %d`, df.QR, df.OPCode, df.TC, df.RD, df.Z, df.NA)
	case DNSReply:
		flags = fmt.Sprintf(`  - Response: Message is a %s
  - Opcode: %s
  - Authoritative: %d
  - Truncated: %d
  - Recursion desired: %d
  - Recursion available: %d
  - Reserved: %d
  - Answer authenticated: %d
  - Non-authenticated data: %d
  - Reply code: %s`,
			df.QR,
			df.OPCode,
			df.AA,
			df.TC,
			df.RD,
			df.RA,
			df.Z,
			df.AU,
			df.NA,
			df.RCode)
	}
	return flags
}

func NewDNSFlags(qr QRFlag, op OpCode, aa, tc, rd, ra, z, au, na bool, rc RCode) *DNSFlags {
	df := &DNSFlags{
		QR:     NewDNSQRFlag(qr),
		OPCode: NewDNSOpCode(op),
		AA:     bTou8(aa),
		TC:     bTou8(tc),
		RD:     bTou8(rd),
		RA:     bTou8(ra),
		Z:      bTou8(z),
		AU:     bTou8(au),
		NA:     bTou8(na),
		RCode:  NewDNSRCode(rc),
	}
	var flags uint16
	flags |= uint16(df.QR.Val) << 15
	flags |= uint16(df.OPCode.Val) << 11
	flags |= uint16(df.AA) << 10
	flags |= uint16(df.TC) << 9
	flags |= uint16(df.RD) << 8
	flags |= uint16(df.RA) << 7
	flags |= uint16(df.Z) << 6
	flags |= uint16(df.AU) << 5
	flags |= uint16(df.NA) << 4
	flags |= uint16(df.RCode.Val)
	df.Raw = flags
	return df
}

func NewDNSFlagsFromRaw(flags uint16) *DNSFlags {
	return &DNSFlags{
		Raw:    flags,
		QR:     NewDNSQRFlag(QRFlag(flags >> 15)),
		OPCode: NewDNSOpCode(OpCode((flags >> 11) & 15)),
		AA:     uint8((flags >> 10) & 1),
		TC:     uint8((flags >> 9) & 1),
		RD:     uint8((flags >> 8) & 1),
		RA:     uint8((flags >> 7) & 1),
		Z:      uint8((flags >> 6) & 1),
		AU:     uint8((flags >> 5) & 1),
		NA:     uint8((flags >> 4) & 1),
		RCode:  NewDNSRCode(RCode(flags & 15)),
	}
}

func qrdesc(qr QRFlag) *DNSQRFlag {
	var qrdesc *DNSQRFlag
	switch qr {
	case 0:
		qrdesc = DNSQuery
	case 1:
		qrdesc = DNSReply
	default:
		qrdesc = &DNSQRFlag{Val: qr, Desc: "Unknown"}
	}
	return qrdesc
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
func getopcode(opcode OpCode) *DNSOpCode {
	var oc *DNSOpCode
	switch opcode {
	case 0:
		oc = DNSOpCodeQuery
	case 1:
		oc = DNSOpCodeInvQuery
	case 2:
		oc = DNSOpCodeStatus
	case 4:
		oc = DNSOpCodeNotify
	case 5:
		oc = DNSOpCodeUpdate
	case 6:
		oc = DNSOpCodeDSO
	default:
		oc = &DNSOpCode{Val: opcode, Desc: "Unknown"}
	}
	return oc
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
func rcdesc(rcode RCode) *DNSRCode {
	var rcdesc *DNSRCode
	switch rcode {
	case RCodeNoError:
		rcdesc = DNSRCodeNoError
	case RCodeFormatError:
		rcdesc = DNSRCodeFormatErr
	case RCodeServerFail:
		rcdesc = DNSRCodeServFail
	case RCodeNameError:
		rcdesc = DNSRCodeNXDomain
	case RCodeNotImpl:
		rcdesc = DNSRCodeNotImpl
	case RCodeRefused:
		rcdesc = DNSRCodeRefused
	case RCodeYXDomain:
		rcdesc = DNSRCodeYXDomain
	case RCodeYXRRSet:
		rcdesc = DNSRCodeYXRRSet
	case RCodeNXRRSet:
		rcdesc = DNSRCodeNXRRSet
	case RCodeNotAuth:
		rcdesc = DNSRCodeNotAuth
	case RCodeNotZone:
		rcdesc = DNSRCodeNotZone
	case RCodeDSOTypeNI:
		rcdesc = DNSRCodeDSOTypeNI
	case RCodeBadVers:
		rcdesc = DNSRCodeBadVers
	case RCodeBadKey:
		rcdesc = DNSRCodeBadKey
	case RCodeBadTime:
		rcdesc = DNSRCodeBadTime
	case RCodeBadMode:
		rcdesc = DNSRCodeBadMode
	case RCodeBadName:
		rcdesc = DNSRCodeBadName
	case RCodeBadAlg:
		rcdesc = DNSRCodeBadAlg
	case RCodeBadTrunc:
		rcdesc = DNSRCodeBadTrunc
	case RCodeBadCookie:
		rcdesc = DNSRCodeBadCookie
	default:
		rcdesc = &DNSRCode{Val: rcode, Desc: "Unknown"}
	}
	return rcdesc
}

func NewDNSMessage(tid uint16, flags *DNSFlags, qd []*QueryEntry, an, ns, ar []*ResourceRecord) (*DNSMessage, error) {
	return &DNSMessage{
		TransactionID: tid,
		Flags:         flags,
		QDCount:       uint16(len(qd)),
		ANCount:       uint16(len(an)),
		NSCount:       uint16(len(ns)),
		ARCount:       uint16(len(ar)),
		Questions:     qd,
		AnswerRRs:     an,
		AuthorityRRs:  ns,
		AdditionalRRs: ar,
	}, nil
}

type DNSMessage struct {
	TransactionID uint16            `json:"transaction-id"`       // Used for matching response to queries.
	Flags         *DNSFlags         `json:"flags,omitempty"`      // Flags specify the requested operation and a response code.
	QDCount       uint16            `json:"questions-count"`      // Count of entries in the queries section.
	ANCount       uint16            `json:"answer-rrs-count"`     //  Count of entries in the answers section.
	NSCount       uint16            `json:"authority-rrs-count"`  // Count of entries in the authority section.
	ARCount       uint16            `json:"additional-rrs-count"` // Count of entries in the additional section.
	Questions     []*QueryEntry     `json:"questions,omitempty"`
	AnswerRRs     []*ResourceRecord `json:"answers,omitempty"`
	AuthorityRRs  []*ResourceRecord `json:"authoritative-nameservers,omitempty"`
	AdditionalRRs []*ResourceRecord `json:"additional-records,omitempty"`
}

func (d *DNSMessage) String() string {
	return fmt.Sprintf(
		`%s
- Transaction ID: %#04x
- Flags: %#04x
%s
- Questions: %d
- Answer RRs: %d
- Authority RRs: %d
- Additional RRs: %d
%s`,
		d.Summary(),
		d.TransactionID,
		d.Flags.Raw,
		d.Flags,
		d.QDCount,
		d.ANCount,
		d.NSCount,
		d.ARCount,
		d.printRecords(),
	)
}

func (d *DNSMessage) Summary() string {
	var sb strings.Builder

	switch d.Flags.QR {
	case DNSReply:
		fmt.Fprintf(&sb, "DNS Message: %s (%s) %s %#04x ", d.Flags.OPCode.Desc, d.Flags.QR.Desc, d.Flags.RCode.Desc, d.TransactionID)
	default:
		fmt.Fprintf(&sb, "DNS Message: %s (%s) %#04x ", d.Flags.OPCode.Desc, d.Flags.QR.Desc, d.TransactionID)
	}
	for _, rec := range d.Questions {
		fmt.Fprintf(&sb, "%s %s ", rec.Type.Name, rec.Name)
		if sb.Len() > maxLenSummary {
			goto result
		}
	}
	for _, rec := range d.AnswerRRs {
		sb.WriteString(rec.Summary())
		if sb.Len() > maxLenSummary {
			goto result
		}
	}
	for _, rec := range d.AuthorityRRs {
		sb.WriteString(rec.Summary())
		if sb.Len() > maxLenSummary {
			goto result
		}
	}
	for _, rec := range d.AdditionalRRs {
		sb.WriteString(rec.Summary())
		if sb.Len() > maxLenSummary {
			goto result
		}
	}
	return sb.String()
result:
	return sb.String()[:maxLenSummary] + string(ellipsis)
}

func (d *DNSMessage) MarshalBinary() ([]byte, error) {
	b := make([]byte, headerSizeDNS)
	binary.BigEndian.PutUint16(b[0:2], d.TransactionID)
	binary.BigEndian.PutUint16(b[2:4], d.Flags.Raw)
	binary.BigEndian.PutUint16(b[4:6], d.QDCount)
	binary.BigEndian.PutUint16(b[6:8], d.ANCount)
	binary.BigEndian.PutUint16(b[8:10], d.NSCount)
	binary.BigEndian.PutUint16(b[10:headerSizeDNS], d.ARCount)
	for _, r := range d.Questions {
		rb, err := r.MarshalBinary()
		if err != nil {
			return nil, err
		}
		b = append(b, rb...)
	}
	for _, r := range d.AnswerRRs {
		rb, err := r.MarshalBinary()
		if err != nil {
			return nil, err
		}
		b = append(b, rb...)
	}
	for _, r := range d.AuthorityRRs {
		rb, err := r.MarshalBinary()
		if err != nil {
			return nil, err
		}
		b = append(b, rb...)
	}
	for _, r := range d.AdditionalRRs {
		rb, err := r.MarshalBinary()
		if err != nil {
			return nil, err
		}
		b = append(b, rb...)
	}
	return b, nil
}

func (d *DNSMessage) ToBytes() []byte {
	b, _ := d.MarshalBinary()
	return b
}

func (d *DNSMessage) UnmarshalBinary(data []byte) error {
	if len(data) < headerSizeDNS {
		return fmt.Errorf("minimum header size for DNS is %d bytes, got %d bytes", headerSizeDNS, len(data))
	}
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	d.TransactionID = binary.BigEndian.Uint16(buf[0:2])
	d.Flags = NewDNSFlagsFromRaw(binary.BigEndian.Uint16(buf[2:4]))
	d.QDCount = binary.BigEndian.Uint16(buf[4:6])
	d.ANCount = binary.BigEndian.Uint16(buf[6:8])
	d.NSCount = binary.BigEndian.Uint16(buf[8:10])
	d.ARCount = binary.BigEndian.Uint16(buf[10:headerSizeDNS])
	var tail []byte
	var err error
	payload := buf[headerSizeDNS:]
	if d.QDCount > 0 {
		d.Questions, tail, err = parseQueries(payload, payload, d.QDCount)
		if err != nil {
			return fmt.Errorf("failed parsing queries: %v", err)
		}
	}
	if d.ANCount > 0 {
		d.AnswerRRs, tail, err = parseResourceRecords(payload, tail, d.ANCount)
		if err != nil {
			return fmt.Errorf("failed parsing answers: %v", err)
		}
	}
	if d.NSCount > 0 {
		d.AuthorityRRs, tail, err = parseResourceRecords(payload, tail, d.NSCount)
		if err != nil {
			return fmt.Errorf("failed parsing authority records: %v", err)
		}
	}
	if d.ARCount > 0 {
		d.AdditionalRRs, _, err = parseResourceRecords(payload, tail, d.ARCount)
		if err != nil {
			return fmt.Errorf("failed parsing additional records: %v", err)
		}
	}
	return nil
}

// Parse parses the given byte data into a DNSMessage struct.
func (d *DNSMessage) Parse(data []byte) error {
	return d.UnmarshalBinary(data)
}

func (d *DNSMessage) NextLayer() Layer { return nil }

func (d *DNSMessage) Name() LayerName { return LayerDNS }

func (d *DNSMessage) printRecords() string {
	var sb strings.Builder
	if d.QDCount > 0 {
		sb.WriteString("- Queries:\n")
		for _, rec := range d.Questions {
			sb.WriteString(rec.String())
		}
	}
	if d.ANCount > 0 {
		sb.WriteString("- Answers:\n")
		for _, rec := range d.AnswerRRs {
			sb.WriteString(rec.String())
		}
	}
	if d.NSCount > 0 {
		sb.WriteString("- Authoritative nameservers:\n")
		for _, rec := range d.AuthorityRRs {
			sb.WriteString(rec.String())
		}
	}
	if d.ARCount > 0 {
		sb.WriteString("- Additional records:\n")
		for _, rec := range d.AdditionalRRs {
			sb.WriteString(strings.TrimSuffix(rec.String(), "\n"))
		}
	}
	return sb.String()
}

type dnsMessageAlias DNSMessage

type dnsQueryWrapper struct {
	Query *dnsMessageAlias `json:"dns_query"`
}
type dnsReplyWrapper struct {
	Reply *dnsMessageAlias `json:"dns_reply"`
}

func (d *DNSMessage) MarshalJSON() ([]byte, error) {
	if d.Flags.QR == DNSReply {
		return json.Marshal(&dnsQueryWrapper{Query: (*dnsMessageAlias)(d)})
	}
	return json.Marshal(&dnsReplyWrapper{Reply: (*dnsMessageAlias)(d)})
}

type RecordClass struct {
	Name string `json:"name"`
	Val  uint16 `json:"val"`
}

func (c *RecordClass) String() string {
	return fmt.Sprintf("%s (%d)", c.Name, c.Val)
}

func NewRecordClass(cls uint16) *RecordClass {
	return &RecordClass{Name: className(cls), Val: cls}
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
func className(cls uint16) string {
	var cname string
	switch cls {
	case 0:
		cname = "Reserved"
	case 1:
		cname = "IN"
	case 3:
		cname = "CH"
	case 4:
		cname = "HS"
	default:
		cname = "Unknown"
	}
	return cname
}

type RecType uint16

const (
	RecTypeA     RecType = 1
	RecTypeNS    RecType = 2
	RecTypeCNAME RecType = 5
	RecTypeSOA   RecType = 6
	RecTypeMX    RecType = 15
	RecTypeTXT   RecType = 16
	RecTypeAAAA  RecType = 28
	RecTypeOPT   RecType = 41
	RecTypeHTTPS RecType = 65
)

type RecordType struct {
	Name string  `json:"name"`
	Val  RecType `json:"val"`
}

func (rt *RecordType) String() string {
	return fmt.Sprintf("%s (%d)", rt.Name, rt.Val) // TODO: new line
}

var (
	DNSRecTypeA     *RecordType = &RecordType{Name: "A", Val: RecTypeA}
	DNSRecTypeNS    *RecordType = &RecordType{Name: "NS", Val: RecTypeNS}
	DNSRecTypeCNAME *RecordType = &RecordType{Name: "CNAME", Val: RecTypeCNAME}
	DNSRecTypeSOA   *RecordType = &RecordType{Name: "SOA", Val: RecTypeSOA}
	DNSRecTypeMX    *RecordType = &RecordType{Name: "MX", Val: RecTypeMX}
	DNSRecTypeTXT   *RecordType = &RecordType{Name: "TXT", Val: RecTypeTXT}
	DNSRecTypeAAAA  *RecordType = &RecordType{Name: "AAAA", Val: RecTypeAAAA}
	DNSRecTypeOPT   *RecordType = &RecordType{Name: "OPT", Val: RecTypeOPT}
	DNSRecTypeHTTPS *RecordType = &RecordType{Name: "HTTPS", Val: RecTypeHTTPS}
)

func NewRecordType(rt RecType) *RecordType {
	return getrectype(rt)
}

func getrectype(rt RecType) *RecordType {
	var typ *RecordType
	switch rt {
	case RecTypeA:
		typ = DNSRecTypeA
	case RecTypeNS:
		typ = DNSRecTypeNS
	case RecTypeCNAME:
		typ = DNSRecTypeCNAME
	case RecTypeSOA:
		typ = DNSRecTypeSOA
	case RecTypeMX:
		typ = DNSRecTypeMX
	case RecTypeTXT:
		typ = DNSRecTypeTXT
	case RecTypeAAAA:
		typ = DNSRecTypeAAAA
	case RecTypeOPT:
		typ = DNSRecTypeOPT
	case RecTypeHTTPS:
		typ = DNSRecTypeHTTPS
	default:
		typ = &RecordType{Name: "Unknown", Val: rt}
	}
	return typ
}

type RData interface {
	fmt.Stringer
	encoding.BinaryMarshaler
	ToBytes() []byte
}

type ResourceRecord struct {
	Name     string       `json:"name"`         // Name of the node to which this record pertains.
	Type     *RecordType  `json:"record-type"`  // Type of RR in numeric form.
	Class    *RecordClass `json:"record-class"` // Class code.
	TTL      uint32       `json:"ttl"`          // Count of seconds that the RR stays valid.
	RDLength uint16       `json:"rdata-length"` // Length of RData field (specified in octets).
	RData    RData        `json:"rdata"`        // Additional RR-specific data.
}

func (rt *ResourceRecord) String() string {
	var record string
	switch rt.Name {
	case "Root":
		name := rt.Name
		if rt.Type.Val == 2 { // NS
			name = rt.RData.(*RDataNS).NsdName
		}
		record = fmt.Sprintf(`  - %s:
    - Name: %s
    - Type: %s
    - %s
`, name, rt.Name, rt.Type, rt.RData)
	default:
		record = fmt.Sprintf(`  - %s:
    - Name: %s
    - Type: %s
    - Class: %s (%d)
    - TTL: %d
    - Data Length: %d
    - %s
`,
			rt.Name,
			rt.Name,
			rt.Type,
			rt.Class.Name,
			rt.Class.Val,
			rt.TTL,
			rt.RDLength,
			rt.RData)
	}
	return record
}

func (rt *ResourceRecord) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)
	b.Write(encodeDomain(rt.Name))
	binary.Write(b, binary.BigEndian, rt.Type.Val)
	binary.Write(b, binary.BigEndian, rt.Class.Val)
	binary.Write(b, binary.BigEndian, rt.TTL)
	binary.Write(b, binary.BigEndian, rt.RDLength)
	rdata, err := rt.RData.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b.Write(rdata)
	return b.Bytes(), nil
}

func (rt *ResourceRecord) ToBytes() []byte {
	b, _ := rt.MarshalBinary()
	return b
}

func (rt *ResourceRecord) Summary() string {
	// TODO: add Summary to RData
	var summary string
	switch rd := rt.RData.(type) {
	case *RDataA:
	case *RDataAAAA:
		summary = fmt.Sprintf("%s %s ", rt.Type.Name, rd.Address)
	case *RDataNS:
		summary = fmt.Sprintf("%s %s ", rt.Type.Name, rd.NsdName)
	case *RDataCNAME:
		summary = fmt.Sprintf("%s %s ", rt.Type.Name, rd.CName)
	case *RDataSOA:
		summary = fmt.Sprintf("%s %s ", rt.Type.Name, rd.PrimaryNS)
	case *RDataMX:
		summary = fmt.Sprintf("%s %d %s ", rt.Type.Name, rd.Preference, rd.Exchange)
	case *RDataTXT:
		summary = fmt.Sprintf("%s %s ", rt.Type.Name, rd.TxtData)
	default:
		summary = fmt.Sprintf("%s ", rt.Type.Name)
	}
	return summary
}

type QueryEntry struct {
	Name  string       `json:"name"`         // Name of the node to which this record pertains.
	Type  *RecordType  `json:"record-type"`  // Type of RR in numeric form.
	Class *RecordClass `json:"record-class"` // Class code.
}

func (qe *QueryEntry) String() string {
	return fmt.Sprintf(`  - %s:
    - Name: %s
    - Type: %s
    - Class: %s (%d)
`, qe.Name, qe.Name, qe.Type, qe.Class.Name, qe.Class.Val)
}

func (qe *QueryEntry) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)
	b.Write(encodeDomain(qe.Name))
	binary.Write(b, binary.BigEndian, qe.Type.Val)
	binary.Write(b, binary.BigEndian, qe.Class.Val)
	return b.Bytes(), nil
}

func (qe *QueryEntry) ToBytes() []byte {
	b, _ := qe.MarshalBinary()
	return b
}

var _ RData = &RDataA{}

type RDataA struct {
	Address netip.Addr `json:"address"`
}

func (d *RDataA) String() string {
	return fmt.Sprintf("Address: %s", d.Address)
}

func (d *RDataA) MarshalBinary() ([]byte, error) {
	return d.Address.AsSlice(), nil
}

func (d *RDataA) ToBytes() []byte {
	b, _ := d.MarshalBinary()
	return b
}

var _ RData = &RDataNS{}

type RDataNS struct {
	NsdName string `json:"ns"`
}

func (d *RDataNS) String() string {
	return fmt.Sprintf("NS: %s", d.NsdName)
}

func (d *RDataNS) MarshalBinary() ([]byte, error) {
	return encodeDomain(d.NsdName), nil
}

func (d *RDataNS) ToBytes() []byte {
	b, _ := d.MarshalBinary()
	return b
}

var _ RData = &RDataCNAME{}

type RDataCNAME struct {
	CName string `json:"cname"`
}

func (d *RDataCNAME) String() string {
	return fmt.Sprintf("CNAME: %s", d.CName)
}

func (d *RDataCNAME) MarshalBinary() ([]byte, error) {
	return encodeDomain(d.CName), nil
}

func (d *RDataCNAME) ToBytes() []byte {
	b, _ := d.MarshalBinary()
	return b
}

var _ RData = &RDataSOA{}

type RDataSOA struct {
	PrimaryNS            string `json:"primary-nameserver"`
	RespAuthorityMailbox string `json:"responsible-authority-mailbox"`
	SerialNumber         uint32 `json:"serial-number"`
	RefreshInterval      uint32 `json:"refresh-interval"`
	RetryInterval        uint32 `json:"retry-interval"`
	ExpireLimit          uint32 `json:"expire-limit"`
	MinimumTTL           uint32 `json:"minimum-ttl"`
}

func (d *RDataSOA) String() string {
	return fmt.Sprintf(`Primary name server: %s
    - Responsible authority's mailbox: %s
    - Serial number: %d
    - Refresh interval: %d
    - Retry interval: %d
    - Expire limit: %d
    - Minimum TTL: %d`,
		d.PrimaryNS,
		d.RespAuthorityMailbox,
		d.SerialNumber,
		d.RefreshInterval,
		d.RetryInterval,
		d.ExpireLimit,
		d.MinimumTTL)
}

func (d *RDataSOA) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)
	b.Write(encodeDomain(d.PrimaryNS))
	b.Write(encodeDomain(d.RespAuthorityMailbox))
	binary.Write(b, binary.BigEndian, d.SerialNumber)
	binary.Write(b, binary.BigEndian, d.RefreshInterval)
	binary.Write(b, binary.BigEndian, d.RetryInterval)
	binary.Write(b, binary.BigEndian, d.ExpireLimit)
	binary.Write(b, binary.BigEndian, d.MinimumTTL)
	return b.Bytes(), nil
}

func (d *RDataSOA) ToBytes() []byte {
	b, _ := d.MarshalBinary()
	return b
}

var _ RData = &RDataMX{}

type RDataMX struct {
	Preference uint16 `json:"preference"`
	Exchange   string `json:"exchange"`
}

func (d *RDataMX) String() string {
	return fmt.Sprintf("MX: %d %s", d.Preference, d.Exchange)
}

func (d *RDataMX) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, d.Preference)
	b.Write(encodeDomain(d.Exchange))
	return b.Bytes(), nil
}

func (d *RDataMX) ToBytes() []byte {
	b, _ := d.MarshalBinary()
	return b
}

var _ RData = &RDataTXT{}

type RDataTXT struct {
	TxtData string `json:"txt-data"`
}

func (d *RDataTXT) String() string {
	return fmt.Sprintf("TXT: %s", d.TxtData)
}

func (d *RDataTXT) MarshalBinary() ([]byte, error) {
	return []byte(d.TxtData), nil
}

func (d *RDataTXT) ToBytes() []byte {
	b, _ := d.MarshalBinary()
	return b
}

var _ RData = &RDataAAAA{}

type RDataAAAA struct {
	Address netip.Addr `json:"address"`
}

func (d *RDataAAAA) String() string {
	return fmt.Sprintf("Address: %s", d.Address)
}

func (d *RDataAAAA) MarshalBinary() ([]byte, error) {
	return d.Address.AsSlice(), nil
}

func (d *RDataAAAA) ToBytes() []byte {
	b, _ := d.MarshalBinary()
	return b
}

var _ RData = &RDataOPT{}

type RDataOPT struct {
	UDPPayloadSize     uint16 `json:"udp-payload-size"`
	HigherBitsExtRCode uint8  `json:"higer-bits-in-extended-rcode"`
	EDNSVer            uint8  `json:"edns0-version"`
	Z                  uint16 `json:"z"`
	DataLen            uint16 `json:"data-length"`
}

func (d *RDataOPT) String() string {
	return fmt.Sprintf(`UDP payload size: %d
    - Higher bits in extended RCODE: %#02x
    - EDNS0 version: %d
    - Z: %d
    - Data Length: %d
`,
		d.UDPPayloadSize,
		d.HigherBitsExtRCode,
		d.EDNSVer,
		d.Z,
		d.DataLen)
}

func (d *RDataOPT) MarshalBinary() ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], d.UDPPayloadSize)
	b[2] = d.HigherBitsExtRCode
	b[3] = d.EDNSVer
	binary.BigEndian.PutUint16(b[4:6], d.Z)
	binary.BigEndian.PutUint16(b[6:8], d.DataLen)
	return b, nil
}

func (d *RDataOPT) ToBytes() []byte {
	b, _ := d.MarshalBinary()
	return b
}

type SvcParamKey struct {
	Val  uint16 `json:"val"`
	Desc string `json:"desc"`
}

// https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml
func svcparamkeydesc(key uint16) string {
	var svcdesc string
	switch key {
	case 0:
		svcdesc = "mandatory"
	case 1:
		svcdesc = "alpn"
	case 2:
		svcdesc = "no-default-alpn"
	case 3:
		svcdesc = "port"
	case 4:
		svcdesc = "ipv4hint"
	case 5:
		svcdesc = "ech"
	case 6:
		svcdesc = "ipv6hint"
	case 7:
		svcdesc = "dohpath"
	case 8:
		svcdesc = "ohttp"
	case 9:
		svcdesc = "tls-supported-groups"
	default:
		svcdesc = "Unknown"
	}
	return svcdesc
}

func newSvcParamKey(key uint16) *SvcParamKey {
	return &SvcParamKey{Val: key, Desc: svcparamkeydesc(key)}
}

func (spk *SvcParamKey) String() string {
	return fmt.Sprintf("%s (%d)", spk.Desc, spk.Val)
}

type SvcParam struct {
	Key    *SvcParamKey `json:"svc-param-key"`
	Length uint16       `json:"svc-param-value-length"`
	Value  []byte       `json:"svc-param-value"` // TODO: add proper parsing
}

func newSvcParam(data []byte) (*SvcParam, []byte, error) {
	if len(data) < 4 {
		return nil, nil, ErrSliceBounds
	}
	key := newSvcParamKey(binary.BigEndian.Uint16(data[0:2]))
	length := binary.BigEndian.Uint16(data[2:4])
	offset := 4 + length
	if offset > uint16(len(data)) {
		return nil, nil, ErrSliceBounds
	}
	value := data[4:offset]
	return &SvcParam{Key: key, Length: length, Value: value}, data[offset:], nil
}

func (sp *SvcParam) String() string {
	return fmt.Sprintf(
		`     - SvcParamKey: %s
     - SvcParamValue length: %d
     - SvcParamValue: %s
`,
		sp.Key,
		sp.Length,
		hex.EncodeToString(sp.Value),
	)
}

func (sp *SvcParam) MarshalBinary() ([]byte, error) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:2], sp.Key.Val)
	binary.BigEndian.PutUint16(b[2:4], sp.Length)
	b = append(b, sp.Value...)
	return b, nil
}

func (sp *SvcParam) ToBytes() []byte {
	b, _ := sp.MarshalBinary()
	return b
}

var _ RData = &RDataHTTPS{}

type RDataHTTPS struct {
	SvcPriority uint16      `json:"svc-priority"`
	Length      int         `json:"length"`
	TargetName  string      `json:"target-name"`
	SvcParams   []*SvcParam `json:"svc-params"`
}

func (d *RDataHTTPS) printSvcParams() string {
	var sb strings.Builder
	for _, p := range d.SvcParams {
		if p == nil {
			continue
		}
		sb.WriteString(p.String())
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (d *RDataHTTPS) String() string {
	return fmt.Sprintf(
		`SvcPriority: %d
    - TargetName: %s
    - SvcParams:
%s`,
		d.SvcPriority,
		d.TargetName,
		d.printSvcParams(),
	)
}

func (d *RDataHTTPS) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, d.SvcPriority)
	b.Write(encodeDomain(d.TargetName))
	for _, p := range d.SvcParams {
		if p == nil {
			continue
		}
		pb, err := p.MarshalBinary()
		if err != nil {
			return nil, err
		}
		b.Write(pb)
	}
	return b.Bytes(), nil
}

func (d *RDataHTTPS) ToBytes() []byte {
	b, _ := d.MarshalBinary()
	return b
}

var _ RData = &RDataUnknown{}

type RDataUnknown struct {
	Data []byte `json:"data"`
}

func (d *RDataUnknown) String() string {
	return hex.EncodeToString(d.Data)
}

func (d *RDataUnknown) MarshalBinary() ([]byte, error) {
	return d.Data, nil
}

func (d *RDataUnknown) ToBytes() []byte {
	b, _ := d.MarshalBinary()
	return b
}

// extractDomain extracts the DNS domain name from the given payload and tail.
//
// The domain name is parsed according to RFC 1035 section 4.1.
func extractDomain(payload, tail []byte) (string, []byte, error) {
	// see https://brunoscheufler.com/blog/2024-05-12-building-a-dns-message-parser#domain-names
	var domainName strings.Builder
	for len(tail) > 0 {
		blen := tail[0]
		if blen>>6 == 0b11 {
			if len(tail) < 2 {
				return "", nil, ErrSliceBounds
			}
			// compressed message offset is 14 bits according to RFC 1035 section 4.1.4
			offset := binary.BigEndian.Uint16(tail[0:2])&(1<<14-1) - headerSizeDNS
			if offset > uint16(len(payload)) {
				return "", nil, ErrSliceBounds
			}
			part, _, err := extractDomain(payload, payload[offset:]) // TODO: iterative approach
			if err != nil {
				return "", nil, err
			}
			domainName.WriteString(part)
			tail = tail[2:]
			break
		}
		tail = tail[1:]
		if blen == 0 {
			break
		}
		if int(blen) > len(tail) {
			return "", nil, ErrSliceBounds
		}
		domainName.WriteString(bytesToStr(tail[0:blen]))
		domainName.WriteString(".")

		tail = tail[blen:]
	}
	return strings.TrimRight(domainName.String(), "."), tail, nil
}

func parseQuery(payload, tail []byte) (*QueryEntry, []byte, error) {
	var domain string
	var err error
	domain, tail, err = extractDomain(payload, tail)
	if err != nil {
		return nil, nil, err
	}
	if len(tail) < 4 {
		return nil, nil, ErrSliceBounds
	}
	typ := binary.BigEndian.Uint16(tail[0:2])
	cls := binary.BigEndian.Uint16(tail[2:4])
	tail = tail[4:]
	return &QueryEntry{
		Name:  domain,
		Type:  NewRecordType(RecType(typ)),
		Class: NewRecordClass(cls),
	}, tail, nil
}

func parseQueries(payload, tail []byte, numRecords uint16) ([]*QueryEntry, []byte, error) {
	queries := make([]*QueryEntry, numRecords)
	var err error
	for i := range queries {
		queries[i], tail, err = parseQuery(payload, tail)
		if err != nil {
			return nil, nil, err
		}
	}
	return queries, tail, nil
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
func parseRData(payload, tail []byte, typ uint16, rdl int) (RData, []byte, error) {
	var rdata RData
	if rdl > len(tail) {
		return nil, nil, ErrSliceBounds
	}
	switch typ {
	case 1:
		addr, ok := netip.AddrFromSlice(tail[0:rdl])
		if !ok {
			return nil, nil, ErrParsingAddress
		}
		rdata = &RDataA{Address: addr}
	case 2:
		domain, _, err := extractDomain(payload, tail)
		if err != nil {
			return nil, nil, err
		}
		rdata = &RDataNS{NsdName: domain}
	case 5:
		domain, _, err := extractDomain(payload, tail)
		if err != nil {
			return nil, nil, err
		}
		rdata = &RDataCNAME{CName: domain}
	case 6:
		var (
			primary string
			mailbox string
			err     error
		)
		ttail := tail
		primary, ttail, err = extractDomain(payload, ttail)
		if err != nil {
			return nil, nil, err
		}
		mailbox, ttail, err = extractDomain(payload, ttail)
		if err != nil {
			return nil, nil, err
		}
		if len(ttail) < 20 {
			return nil, nil, ErrSliceBounds
		}
		serial := binary.BigEndian.Uint32(ttail[0:4])
		refresh := binary.BigEndian.Uint32(ttail[4:8])
		retry := binary.BigEndian.Uint32(ttail[8:12])
		expire := binary.BigEndian.Uint32(ttail[12:16])
		minttl := binary.BigEndian.Uint32(ttail[16:20])
		rdata = &RDataSOA{
			PrimaryNS:            primary,
			RespAuthorityMailbox: mailbox,
			SerialNumber:         serial,
			RefreshInterval:      refresh,
			RetryInterval:        retry,
			ExpireLimit:          expire,
			MinimumTTL:           minttl,
		}
	case 15:
		preference := binary.BigEndian.Uint16(tail[0:2])
		domain, _, err := extractDomain(payload, tail[2:rdl])
		if err != nil {
			return nil, nil, err
		}
		rdata = &RDataMX{
			Preference: preference,
			Exchange:   domain,
		}
	case 16:
		rdata = &RDataTXT{TxtData: string(tail[:rdl])}
	case 28:
		addr, ok := netip.AddrFromSlice(tail[0:rdl])
		if !ok {
			return nil, nil, ErrParsingAddress
		}
		rdata = &RDataAAAA{Address: addr}
	case 41:
		if len(tail) < 8 {
			return nil, nil, ErrSliceBounds
		}
		ups := binary.BigEndian.Uint16(tail[0:2])
		hb := tail[2]
		ednsv := tail[3]
		zres := binary.BigEndian.Uint16(tail[4:6])
		tail = tail[8:]
		rdata = &RDataOPT{
			UDPPayloadSize:     ups,
			HigherBitsExtRCode: hb,
			EDNSVer:            ednsv,
			Z:                  zres,
			DataLen:            uint16(rdl),
		}
	case 65:
		if len(tail) < 3 {
			return nil, nil, ErrSliceBounds
		}
		priority := binary.BigEndian.Uint16(tail[0:2])
		nameLength := tail[2]
		var target string
		var err error
		ttail := tail[:rdl]
		if nameLength == 0 {
			target = "Root"
			ttail = ttail[3:]
		} else {
			target, ttail, err = extractDomain(payload, ttail[2:])
			if err != nil {
				return nil, nil, err
			}
		}
		svcParams := make([]*SvcParam, 10)
		var svcParam *SvcParam
		for len(ttail) > 0 {
			svcParam, ttail, err = newSvcParam(ttail)
			if err != nil {
				return nil, nil, err
			}
			if svcParam.Key.Desc == "Unknown" {
				continue
			}
			svcParams[svcParam.Key.Val] = svcParam
		}
		rdata = &RDataHTTPS{SvcPriority: priority, Length: int(nameLength), TargetName: target, SvcParams: svcParams}
	default:
		rdata = &RDataUnknown{Data: tail[:rdl]}
	}
	if rdl > len(tail) {
		return nil, nil, ErrSliceBounds
	}
	return rdata, tail[rdl:], nil
}

func parseResourceRecord(payload, tail []byte) (*ResourceRecord, []byte, error) {
	var domain string
	var err error
	recordClass := &RecordClass{}
	var rdlLength uint16 = 0
	offset := 10
	domain, tail, err = extractDomain(payload, tail)
	if err != nil {
		return nil, nil, err
	}
	if len(tail) < offset {
		return nil, nil, ErrSliceBounds
	}
	typ := binary.BigEndian.Uint16(tail[0:2])
	cls := binary.BigEndian.Uint16(tail[2:4])
	ttl := binary.BigEndian.Uint32(tail[4:8])
	rdl := binary.BigEndian.Uint16(tail[8:offset])
	var rdata RData
	if domain == "" && typ == 41 { // NOTE: ugly
		offset = 2
	}
	rdata, tail, err = parseRData(payload, tail[offset:], typ, int(rdl))
	if err != nil {
		return nil, nil, err
	}
	if domain == "" {
		domain = "Root"
		ttl = 0
	} else {
		recordClass = NewRecordClass(cls)
		rdlLength = rdl
	}
	return &ResourceRecord{
		Name:     domain,
		Type:     NewRecordType(RecType(typ)),
		Class:    recordClass,
		TTL:      ttl,
		RDLength: rdlLength,
		RData:    rdata,
	}, tail, nil
}

func parseResourceRecords(payload, tail []byte, numRecords uint16) ([]*ResourceRecord, []byte, error) {
	records := make([]*ResourceRecord, numRecords)
	var err error
	for i := range records {
		records[i], tail, err = parseResourceRecord(payload, tail)
		if err != nil {
			return nil, nil, err
		}
	}
	return records, tail, nil
}

func encodeDomain(name string) []byte {
	if name == "Root" {
		return []byte{0}
	}
	var out []byte
	for l := range strings.SplitSeq(name, ".") {
		out = append(out, byte(len(l)))
		out = append(out, []byte(l)...)
	}
	out = append(out, 0)
	return out
}
