package layers

import (
	"encoding/binary"
	"encoding/hex"
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
	sb.WriteString(fmt.Sprintf("DNS Message: %s (%s) %#04x ", d.Flags.OPCodeDesc, d.Flags.QRDesc, d.TransactionID))
	for _, rec := range d.Questions {
		sb.WriteString(fmt.Sprintf("%s %s ", rec.Type.Name, rec.Name))
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

func (d *DNSMessage) UnmarshalBinary(data []byte) error {
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
	return strings.TrimSuffix(sb.String(), "\n")
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

func (rt *ResourceRecord) Summary() string {
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

type SvcParamKey struct {
	Val  uint16
	Desc string
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
	Key    *SvcParamKey
	Length uint16
	Value  []byte // TODO: add proper parsing
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
	return fmt.Sprintf(`     - SvcParamKey: %s
     - SvcParamValue length: %d
     - SvcParamValue: %s
`,
		sp.Key,
		sp.Length,
		hex.EncodeToString(sp.Value),
	)
}

type RDataHTTPS struct {
	SvcPriority uint16
	Length      int
	TargetName  string
	SvcParams   []*SvcParam
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
	return fmt.Sprintf(`SvcPriority: %d
    - TargetName: %s
    - SvcParams:
%s`,
		d.SvcPriority,
		d.TargetName,
		d.printSvcParams(),
	)
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
func extractDomain(payload, tail []byte) (string, []byte, error) {
	// see https://brunoscheufler.com/blog/2024-05-12-building-a-dns-message-parser#domain-names
	var domainName string
	for {
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
			domainName += part
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
		domainName += bytesToStr(tail[0:blen])
		domainName += "."

		tail = tail[blen:]
	}
	return strings.TrimRight(domainName, "."), tail, nil
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
		Type:  newRecordType(typ),
		Class: newRecordClass(cls),
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
func parseRData(payload, tail []byte, typ uint16, rdl int) (fmt.Stringer, []byte, error) {
	var rdata fmt.Stringer
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
		priority := binary.BigEndian.Uint16(tail[0:2])
		nameLength := tail[2]
		var target string
		var err error
		ttail := tail[:rdl]
		if nameLength == 0 {
			target = "Root"
			ttail = ttail[3:]
		} else {
			target, ttail, err = extractDomain(payload, ttail)
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
		rdata = &RDataUnknown{Data: string(tail[:rdl])}
	}
	if rdl > len(tail) {
		return nil, nil, ErrSliceBounds
	}
	return rdata, tail[rdl:], nil
}

func parseRoot(payload, tail []byte) (*ResourceRecord, []byte, error) {
	if len(tail) < 10 {
		return nil, nil, ErrSliceBounds
	}
	typ := binary.BigEndian.Uint16(tail[0:2])
	rdl := int(binary.BigEndian.Uint16(tail[8:10]))
	var rdata fmt.Stringer
	var err error
	rdata, tail, err = parseRData(payload, tail[2:], typ, rdl)
	if err != nil {
		return nil, nil, err
	}
	return &ResourceRecord{
		Name:  "Root",
		Type:  newRecordType(typ),
		Class: &RecordClass{},
		RData: rdata,
	}, tail, nil
}

func parseResourceRecord(payload, tail []byte) (*ResourceRecord, []byte, error) {
	var domain string
	var err error
	domain, tail, err = extractDomain(payload, tail)
	if err != nil {
		return nil, nil, err
	}
	if len(tail) < 10 {
		return nil, nil, ErrSliceBounds
	}
	typ := binary.BigEndian.Uint16(tail[0:2])
	cls := binary.BigEndian.Uint16(tail[2:4])
	ttl := binary.BigEndian.Uint32(tail[4:8])
	rdl := binary.BigEndian.Uint16(tail[8:10])
	var rdata fmt.Stringer
	rdata, tail, err = parseRData(payload, tail[10:], typ, int(rdl))
	if err != nil {
		return nil, nil, err
	}
	return &ResourceRecord{
		Name:     domain,
		Type:     newRecordType(typ),
		Class:    newRecordClass(cls),
		TTL:      ttl,
		RDLength: rdl,
		RData:    rdata,
	}, tail, nil
}

func parseResourceRecords(payload, tail []byte, numRecords uint16) ([]*ResourceRecord, []byte, error) {
	if len(tail) < 1 {
		return nil, nil, ErrSliceBounds
	}
	records := make([]*ResourceRecord, numRecords)
	var err error
	for i := range records {
		if tail[0] != 0 {
			records[i], tail, err = parseResourceRecord(payload, tail)
			if err != nil {
				return nil, nil, err
			}
		} else {
			records[i], tail, err = parseRoot(payload, tail[1:])
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return records, tail, nil
}
