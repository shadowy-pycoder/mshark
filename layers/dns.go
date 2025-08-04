package layers

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

const headerSizeDNS = 12

type DNSFlags struct {
	Raw        uint16
	QR         uint8  // Indicates if the message is a query (0) or a reply (1).
	QRDesc     string // Query (0) or Reply (1)
	OPCode     uint8  // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
	OPCodeDesc string
	AA         uint8 // Authoritative Answer, in a response, indicates if the DNS server is authoritative for the queried hostname.
	TC         uint8 // TrunCation, indicates that this message was truncated due to excessive length.
	RD         uint8 // Recursion Desired, indicates if the client means a recursive query.
	RA         uint8 // Recursion Available, in a response, indicates if the replying DNS server supports recursion.
	Z          uint8 // Zero, reserved for future use.
	AU         uint8 // Indicates if answer/authority portion was authenticated by the server.
	NA         uint8 // Indicates if non-authenticated data is accepatable.
	RCode      uint8 // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
	RCodeDesc  string
}

func (df *DNSFlags) String() string {
	var flags string
	switch df.QR {
	case 0:
		flags = fmt.Sprintf(`  - Response: Message is a %s (%d)
  - Opcode: %s (%d)
  - Truncated: %d
  - Recursion desired: %d
  - Reserved: %d
  - Non-authenticated data: %d`, df.QRDesc, df.QR, df.OPCodeDesc, df.OPCode, df.TC, df.RD, df.Z, df.NA)
	case 1:
		flags = fmt.Sprintf(`  - Response: Message is a %s (%d)
  - Opcode: %s (%d)
  - Authoritative: %d
  - Truncated: %d
  - Recursion desired: %d
  - Recursion available: %d
  - Reserved: %d
  - Answer authenticated: %d
  - Non-authenticated data: %d
  - Reply code: %s (%d)`,
			df.QRDesc,
			df.QR,
			df.OPCodeDesc,
			df.OPCode,
			df.AA,
			df.TC,
			df.RD,
			df.RA,
			df.Z,
			df.AU,
			df.NA,
			df.RCodeDesc,
			df.RCode)
	}
	return flags
}

func newDNSFlags(flags uint16) *DNSFlags {
	qr := uint8(flags >> 15)
	opcode := uint8((flags >> 11) & 15)
	rcode := uint8(flags & 15)
	return &DNSFlags{
		Raw:        flags,
		QR:         qr,
		QRDesc:     qrdesc(qr),
		OPCode:     opcode,
		OPCodeDesc: opcdesc(opcode),
		AA:         uint8((flags >> 10) & 1),
		TC:         uint8((flags >> 9) & 1),
		RD:         uint8((flags >> 8) & 1),
		RA:         uint8((flags >> 7) & 1),
		Z:          uint8((flags >> 6) & 1),
		AU:         uint8((flags >> 5) & 1),
		NA:         uint8((flags >> 4) & 1),
		RCode:      rcode,
		RCodeDesc:  rcdesc(rcode),
	}
}

func qrdesc(qr uint8) string {
	var qrdesc string
	switch qr {
	case 0:
		qrdesc = "query"
	case 1:
		qrdesc = "reply"
	}
	return qrdesc
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
func opcdesc(opcode uint8) string {
	var opcdesc string
	switch opcode {
	case 0:
		opcdesc = "Standard query"
	case 1:
		opcdesc = "Inverse query"
	case 2:
		opcdesc = "Server status request"
	case 4:
		opcdesc = "Notify"
	case 5:
		opcdesc = "Update"
	case 6:
		opcdesc = "Stateful operation"
	default:
		opcdesc = "Unknown"
	}
	return opcdesc
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
func rcdesc(rcode uint8) string {
	var rcdesc string
	switch rcode {
	case 0:
		rcdesc = "No error"
	case 1:
		rcdesc = "Format error"
	case 2:
		rcdesc = "Server failed to complete the DNS request"
	case 3:
		rcdesc = "Domain name does not exist"
	case 4:
		rcdesc = "Function not implemented"
	case 5:
		rcdesc = "The server refused to answer for the query"
	case 6:
		rcdesc = "Name that should not exist, does exist"
	case 7:
		rcdesc = "RRset that should not exist, does exist"
	case 8:
		rcdesc = "Server not authoritative for the zone"
	case 9:
		rcdesc = "Server Not Authoritative for zone"
	case 10:
		rcdesc = "Name not contained in zone"
	case 11:
		rcdesc = "DSO-TYPE Not Implemented"
	case 16:
		rcdesc = "Bad OPT Version/TSIG Signature Failure"
	case 17:
		rcdesc = "Key not recognizede"
	case 18:
		rcdesc = "Signature out of time window"
	case 19:
		rcdesc = "Bad TKEY Mode"
	case 20:
		rcdesc = "Duplicate key name"
	case 21:
		rcdesc = "Algorithm not supported"
	case 22:
		rcdesc = "Bad Truncation"
	case 23:
		rcdesc = "Bad/missing Server Cookie"
	default:
		rcdesc = "Unknown"
	}
	return rcdesc
}

type DNSMessage struct {
	TransactionID uint16    // Used for matching response to queries.
	Flags         *DNSFlags // Flags specify the requested operation and a response code.
	QDCount       uint16    // Count of entries in the queries section.
	ANCount       uint16    //  Count of entries in the answers section.
	NSCount       uint16    // Count of entries in the authority section.
	ARCount       uint16    // Count of entries in the additional section.
	Questions     []*QueryEntry
	AnswerRRs     []*ResourceRecord
	AuthorityRRs  []*ResourceRecord
	AdditionalRRs []*ResourceRecord
}

func (d *DNSMessage) String() string {
	return fmt.Sprintf(`%s
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
	sb.WriteString(fmt.Sprintf("DNS Message: %s %s %#04x ", d.Flags.OPCodeDesc, d.Flags.QRDesc, d.TransactionID))
	for _, rec := range d.Questions {
		sb.WriteString(fmt.Sprintf("%s %s ", rec.Type.Name, rec.Name))
		if sb.Len() > maxLenSummary {
			goto result
		}
	}
	for _, rec := range d.AnswerRRs {
		sb.WriteString(fmt.Sprintf("%s %s ", rec.Type.Name, rec.Name))
		if sb.Len() > maxLenSummary {
			goto result
		}
	}
	for _, rec := range d.AuthorityRRs {
		sb.WriteString(fmt.Sprintf("%s %s ", rec.Type.Name, rec.Name))
		if sb.Len() > maxLenSummary {
			goto result
		}
	}
	for _, rec := range d.AdditionalRRs {
		sb.WriteString(fmt.Sprintf("%s %s ", rec.Type.Name, rec.Name))
		if sb.Len() > maxLenSummary {
			goto result
		}
	}
	return sb.String()
result:
	return sb.String()[:maxLenSummary] + string(ellipsis)
}

// Parse parses the given byte data into a DNSMessage struct.
func (d *DNSMessage) Parse(data []byte) error {
	if len(data) < headerSizeDNS {
		return fmt.Errorf("minimum header size for DNS is %d bytes, got %d bytes", headerSizeDNS, len(data))
	}
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	d.TransactionID = binary.BigEndian.Uint16(buf[0:2])
	d.Flags = newDNSFlags(binary.BigEndian.Uint16(buf[2:4]))
	d.QDCount = binary.BigEndian.Uint16(buf[4:6])
	d.ANCount = binary.BigEndian.Uint16(buf[6:8])
	d.NSCount = binary.BigEndian.Uint16(buf[8:10])
	d.ARCount = binary.BigEndian.Uint16(buf[10:headerSizeDNS])
	var tail []byte
	payload := buf[headerSizeDNS:]
	d.Questions = nil
	d.AnswerRRs = nil
	d.AuthorityRRs = nil
	d.AdditionalRRs = nil
	if d.QDCount > 0 {
		d.Questions, tail = parseQueries(payload, payload, d.QDCount)
	}
	if d.ANCount > 0 {
		d.AnswerRRs, tail = parseResourceRecords(payload, tail, d.ANCount)
	}
	if d.NSCount > 0 {
		d.AuthorityRRs, tail = parseResourceRecords(payload, tail, d.NSCount)
	}
	if d.ARCount > 0 {
		d.AdditionalRRs, _ = parseResourceRecords(payload, tail, d.ARCount)
	}
	return nil
}

func (d *DNSMessage) NextLayer() (layer string, payload []byte) { return }

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
			sb.WriteString(rec.String())
		}
	}
	return sb.String()
}

type RecordClass struct {
	Name string
	Val  uint16
}

func (c *RecordClass) String() string {
	return fmt.Sprintf("%s (%d)", c.Name, c.Val)
}

func newRecordClass(cls uint16) *RecordClass {
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

type RecordType struct {
	Name string
	Val  uint16
}

func (rt *RecordType) String() string {
	return fmt.Sprintf("%s (%d)", rt.Name, rt.Val) // TODO: new line
}

func newRecordType(typ uint16) *RecordType {
	return &RecordType{Name: typeName(typ), Val: typ}
}

func typeName(typ uint16) string {
	var typedesc string
	switch typ {
	case 1:
		typedesc = "A"
	case 2:
		typedesc = "NS"
	case 5:
		typedesc = "CNAME"
	case 6:
		typedesc = "SOA"
	case 15:
		typedesc = "MX"
	case 16:
		typedesc = "TXT"
	case 28:
		typedesc = "AAAA"
	case 41:
		typedesc = "OPT"
	case 65:
		typedesc = "HTTPS"
	default:
		typedesc = "Unknown"
	}
	return typedesc
}

type ResourceRecord struct {
	Name     string       // Name of the node to which this record pertains.
	Type     *RecordType  // Type of RR in numeric form.
	Class    *RecordClass // Class code.
	TTL      uint32       // Count of seconds that the RR stays valid.
	RDLength uint16       // Length of RData field (specified in octets).
	RData    fmt.Stringer // Additional RR-specific data.
}

func (rt *ResourceRecord) String() string {
	var record string
	switch rt.Name {
	case "Root":
		record = fmt.Sprintf(`  - %s:
    - Name: %s
    - Type: %s (%d)
    - %s
`, rt.Name, rt.Name, rt.Type.Name, rt.Type.Val, rt.RData)
	default:
		record = fmt.Sprintf(`  - %s:
    - Name: %s
    - Type: %s (%d)
    - Class: %s (%d)
    - TTL: %d
    - Data Length: %d
    - %s
`,
			rt.Name,
			rt.Name,
			rt.Type.Name,
			rt.Type.Val,
			rt.Class.Name,
			rt.Class.Val,
			rt.TTL,
			rt.RDLength,
			rt.RData)
	}
	return record
}

type QueryEntry struct {
	Name  string       // Name of the node to which this record pertains.
	Type  *RecordType  // Type of RR in numeric form.
	Class *RecordClass // Class code.
}

func (qe *QueryEntry) String() string {
	return fmt.Sprintf(`  - %s:
    - Name: %s
    - Type: %s (%d)
    - Class: %s (%d)
`, qe.Name, qe.Name, qe.Type.Name, qe.Type.Val, qe.Class.Name, qe.Class.Val)
}

type RDataA struct {
	Address netip.Addr
}

func (d *RDataA) String() string {
	return fmt.Sprintf("Address: %s", d.Address)
}

type RDataNS struct {
	NsdName string
}

func (d *RDataNS) String() string {
	return fmt.Sprintf("NS: %s", d.NsdName)
}

type RDataCNAME struct {
	CName string
}

func (d *RDataCNAME) String() string {
	return fmt.Sprintf("CNAME: %s", d.CName)
}

type RDataSOA struct {
	PrimaryNS            string
	RespAuthorityMailbox string
	SerialNumber         uint32
	RefreshInterval      uint32
	RetryInterval        uint32
	ExpireLimit          uint32
	MinimumTTL           uint32
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

type RDataMX struct {
	Preference uint16
	Exchange   string
}

func (d *RDataMX) String() string {
	return fmt.Sprintf("MX: %d %s", d.Preference, d.Exchange)
}

type RDataTXT struct {
	TxtData string
}

func (d *RDataTXT) String() string {
	return fmt.Sprintf("TXT: %s", d.TxtData)
}

type RDataAAAA struct {
	Address netip.Addr
}

func (d *RDataAAAA) String() string {
	return fmt.Sprintf("Address: %s", d.Address)
}

type RDataOPT struct {
	UDPPayloadSize     uint16
	HigherBitsExtRCode uint8
	EDNSVer            uint8
	Z                  uint16
	DataLen            uint16
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

type RDataHTTPS struct {
	Data string // TODO: add proper parsing
}

func (d *RDataHTTPS) String() string {
	return d.Data
}

type RDataUnknown struct {
	Data string
}

func (d *RDataUnknown) String() string {
	return d.Data
}

// extractDomain extracts the DNS domain name from the given payload and tail.
//
// The domain name is parsed according to RFC 1035 section 4.1.
func extractDomain(payload, tail []byte) (string, []byte) {
	// see https://brunoscheufler.com/blog/2024-05-12-building-a-dns-message-parser#domain-names
	var domainName string
	for {
		blen := tail[0]
		if blen>>6 == 0b11 {
			// compressed message offset is 14 bits according to RFC 1035 section 4.1.4
			offset := binary.BigEndian.Uint16(tail[0:2])&(1<<14-1) - headerSizeDNS
			part, _ := extractDomain(payload, payload[offset:]) // TODO: iterative approach
			domainName += part
			tail = tail[2:]
			break
		}
		tail = tail[1:]
		if blen == 0 {
			break
		}
		domainName += bytesToStr(tail[0:blen])
		domainName += "."

		tail = tail[blen:]
	}
	return strings.TrimRight(domainName, "."), tail
}

func parseQuery(payload, tail []byte) (*QueryEntry, []byte) {
	var domain string
	domain, tail = extractDomain(payload, tail)
	typ := binary.BigEndian.Uint16(tail[0:2])
	cls := binary.BigEndian.Uint16(tail[2:4])
	tail = tail[4:]
	return &QueryEntry{
		Name:  domain,
		Type:  newRecordType(typ),
		Class: newRecordClass(cls),
	}, tail
}

func parseQueries(payload, tail []byte, numRecords uint16) ([]*QueryEntry, []byte) {
	queries := make([]*QueryEntry, numRecords)
	for i := range queries {
		queries[i], tail = parseQuery(payload, tail)
	}
	return queries, tail
}

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
func parseRData(payload, tail []byte, typ uint16, rdl int) (fmt.Stringer, []byte) {
	var rdata fmt.Stringer
	switch typ {
	case 1:
		addr, _ := netip.AddrFromSlice(tail[0:rdl])
		rdata = &RDataA{Address: addr}
	case 2:
		domain, _ := extractDomain(payload, tail)
		rdata = &RDataNS{NsdName: domain}
	case 5:
		domain, _ := extractDomain(payload, tail)
		rdata = &RDataCNAME{CName: domain}
	case 6:
		var (
			primary string
			mailbox string
		)
		ttail := tail
		primary, ttail = extractDomain(payload, ttail)
		mailbox, ttail = extractDomain(payload, ttail)
		serial := binary.BigEndian.Uint32(ttail[0:4])
		refresh := binary.BigEndian.Uint32(ttail[4:8])
		retry := binary.BigEndian.Uint32(ttail[8:12])
		expire := binary.BigEndian.Uint32(ttail[12:16])
		min := binary.BigEndian.Uint32(ttail[16:20])
		rdata = &RDataSOA{
			PrimaryNS:            primary,
			RespAuthorityMailbox: mailbox,
			SerialNumber:         serial,
			RefreshInterval:      refresh,
			RetryInterval:        retry,
			ExpireLimit:          expire,
			MinimumTTL:           min,
		}
	case 15:
		preference := binary.BigEndian.Uint16(tail[0:2])
		domain, _ := extractDomain(payload, tail[2:rdl])
		rdata = &RDataMX{
			Preference: preference,
			Exchange:   domain,
		}
	case 16:
		rdata = &RDataTXT{TxtData: string(tail[:rdl])}
	case 28:
		addr, _ := netip.AddrFromSlice(tail[0:rdl])
		rdata = &RDataAAAA{Address: addr}
	case 41:
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
		rdata = &RDataHTTPS{Data: string(tail[:rdl])}
	default:
		rdata = &RDataUnknown{Data: string(tail[:rdl])}
	}
	return rdata, tail[rdl:]
}

func parseRoot(payload, tail []byte) (*ResourceRecord, []byte) {
	typ := binary.BigEndian.Uint16(tail[0:2])
	rdl := int(binary.BigEndian.Uint16(tail[8:10]))
	var rdata fmt.Stringer
	rdata, tail = parseRData(payload, tail[2:], typ, rdl)
	return &ResourceRecord{
		Name:  "Root",
		Type:  newRecordType(typ),
		Class: &RecordClass{},
		RData: rdata,
	}, tail
}

func parseResourceRecord(payload, tail []byte) (*ResourceRecord, []byte) {
	var domain string
	domain, tail = extractDomain(payload, tail)
	typ := binary.BigEndian.Uint16(tail[0:2])
	cls := binary.BigEndian.Uint16(tail[2:4])
	ttl := binary.BigEndian.Uint32(tail[4:8])
	rdl := binary.BigEndian.Uint16(tail[8:10])
	var rdata fmt.Stringer
	rdata, tail = parseRData(payload, tail[10:], typ, int(rdl))
	return &ResourceRecord{
		Name:     domain,
		Type:     newRecordType(typ),
		Class:    newRecordClass(cls),
		TTL:      ttl,
		RDLength: rdl,
		RData:    rdata,
	}, tail
}

func parseResourceRecords(payload, tail []byte, numRecords uint16) ([]*ResourceRecord, []byte) {
	records := make([]*ResourceRecord, numRecords)
	for i := range records {
		if tail[0] != 0 {
			records[i], tail = parseResourceRecord(payload, tail)
		} else {
			records[i], tail = parseRoot(payload, tail[1:])
		}
	}
	return records, tail
}
