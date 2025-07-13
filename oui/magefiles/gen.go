package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"go/format"
	"io"
	"log"
	"maps"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"unicode"

	"github.com/magefile/mage/mg"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var codeTemplate = `
package oui // generated code - do not edit

var ouis = map[string]int{
{{- range .Entries }}
"{{ .OUI }}": {{ .VendorID }}, // {{ .Vendor }}
{{- end }}
}

var vendors = []string{
{{- range .Vendors }}
"{{ . }}",
{{- end }}
}

var vendorsFull = []string{
{{- range .VendorsFull }}
"{{ . }}",
{{- end }}
}

`
var caser = cases.Title(language.English)

func IsUpper(s string) bool {
	for _, r := range s {
		if !unicode.IsUpper(r) && unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

var sr = strings.NewReplacer(
	",.",
	"/",
	".,",
	"/",
	". ,",
	"/",
	", .",
	"/",
	" . ",
	"/",
	". ",
	"/",
	" .",
	"/",
	".",
	"/",
	" , ",
	"/",
	", ",
	"/",
	" ,",
	"/",
	",",
	"/",
	"，",
	"/",
	" a ",
	" ",
	" & ",
	" ",
	"&",
	" ",
	"(",
	"",
	")",
	"",
	"'",
	" ",
	"-",
	" ",
	"*",
	"",
	"/",
	"",
	"\"",
	"",
	"`",
	" ",
	" – ",
	" ",
)

// https://github.com/wireshark/wireshark/blob/master/tools/make-manuf.py
var terms = []string{
	`a +s\b`,
	`ab\b`,
	`ag\b`,
	`b ?v\b`,
	`closed joint stock company\b`,
	`co\b`,
	`company\b`,
	`corp\b`,
	`corporation\b`,
	`corporate\b`,
	`de c ?v\b`,
	`gmbh\b`,
	`holding\b`,
	`inc\b`,
	`incorporated\b`,
	`jsc\b`,
	`kg\b`,
	`k k\b`,
	`limited\b`,
	`llc\b`,
	`ltd\b`,
	`n ?v\b`,
	`oao\b`,
	`of\b`,
	`open joint stock company\b`,
	`ooo\b`,
	`oü\b`,
	`oy\b`,
	`oyj\b`,
	`plc\b`,
	`pty\b`,
	`pvt\b`,
	`s ?a ?r ?l\b`,
	`s ?a\b`,
	`s ?p ?a\b`,
	`sp ?k\b`,
	`s ?r ?l\b`,
	`systems\b`,
	`\bthe\b`,
	`zao\b`,
	`z ?o ?o\b`,
}

var pattern = regexp.MustCompile(`(?i)\b(?:` + strings.Join(terms, "|") + `)`)

type templateData struct {
	Entries     []entry
	Vendors     []string
	VendorsFull []string
}

type OUI string

type entry struct {
	OUI      OUI
	VendorID int
	Vendor   string
}

func (o OUI) String() string {
	return string(o)
}

func (o OUI) Int() int64 {
	n, err := strconv.ParseInt(o.String(), 16, 64)
	if err != nil {
		panic(err)
	}

	return n
}

// https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml
// Unicast
// 00-00-00 to 00-00-FF 	Reserved 	[RFC9542]
// 00-01-00 to 00-01-FF 	VRRP (Virtual Router Redundancy Protocol) 	[RFC9568]
// 00-02-00 to 00-02-FF 	VRRP IPv6 (Virtual Router Redundancy Protocol IPv6) 	[RFC9568]
// 00-03-00 to 00-51-FF 	Unassigned
// 00-52-00 	PacketPWEthA 	[RFC6658]
// 00-52-01 	PacketPWEthB 	[RFC6658]
// 00-52-02 	BFD for VXLAN 	[RFC8971]
// 00-52-03 to 00-52-12 	Unassigned (small allocations)
// 00-52-13 	Proxy Mobile IPv6 	[RFC6543]
// 00-52-14 to 00-52-FF 	Unassigned (small allocations)
// 00-53-00 to 00-53-FF 	Documentation 	[RFC9542]
// 00-54-00 to 90-00-FF 	Unassigned
// 90-01-00 	TRILL OAM 	[RFC7455]
// 90-01-01 to 90-01-FF 	Unassigned (small allocations requiring both unicast and multicast)
// 90-02-00 to FF-FF-FF 	Unassigned
// Multicast
// 00-00-00 to 7F-FF-FF 	IPv4 Multicast 	[RFC1112]
// 80-00-00 to 8F-FF-FF 	MPLS Multicast 	[RFC5332]
// 90-00-00 	MPLS-TP p2p 	[RFC7213]
// 90-00-01 	Bidirectional Forwarding Detection (BFD) on Link Aggregation Group (LAG) Interfaces 	[RFC7130]
// 90-00-02 	AllL1MI-ISs 	[RFC8202]
// 90-00-03 	AllL2MI-ISs 	[RFC8202]
// 90-00-04 to 90-00-FF 	Unassigned (small allocations)
// 90-01-00 	TRILL OAM 	[RFC7455]
// 90-01-01 to 90-01-FF 	Unassigned (small allocations requiring both unicast and multicast)
// 90-02-00 to 90-0F-FF 	Unassigned
// 90-10-00 to 90-10-FF 	Documentation 	[RFC9542]
// 90-11-00 to FF-FF-FF 	Unassigned
func genEthernetNumbersMap() map[string]string {
	en := make(map[string]string)
	// Unicast assignments
	// genFromRange("000100", "0001ff", "VRRP", en)
	// genFromRange("000200", "0002ff", "VRRPv6", en)
	en["005200"] = "PacketPWEthA"
	en["005201"] = "PacketPWEthB"
	en["005202"] = "BFD for VXLAN"
	en["005213"] = "Proxy Mobile IPv6"
	genFromRange("005300", "0053ff", "Documentation", en)
	en["900100"] = "TRILL OAM"

	// Multicast assignments
	en["01005e"] = "IPv4 Multicast" // actually max value is 01-00-5E-7F-FF-FF
	genFromRange("333300", "3333ff", "IPv6 Multicast", en)
	// genFromRange("800000", "8fffff", "MPLS Multicast", en)
	en["900000"] = "MPLS TP p2p"
	en["900001"] = "BFD on LAG Interfaces"
	en["900002"] = "AllL1MI ISs"
	en["900003"] = "AllL2MI ISs"
	en["900100"] = "TRILL OAM"
	genFromRange("901000", "9010ff", "Documentation", en)
	return en
}

func genFromRange(low, high, name string, en map[string]string) {
	l, err := strconv.ParseInt(low, 16, 64)
	if err != nil {
		panic(err)
	}
	h, err := strconv.ParseInt(high, 16, 64)
	if err != nil {
		panic(err)
	}
	for i := l; i <= h; i++ {
		en[fmt.Sprintf("%06x", i)] = name
	}
}

func generate(src, dst string) error {
	mg.Deps(download)

	fin, err := os.Open(src)
	if err != nil {
		return err
	}
	defer fin.Close()

	data := newTemplateData(fin)

	tmpl, err := template.New("oui").Parse(codeTemplate)
	if err != nil {
		return err
	}

	var buf bytes.Buffer

	if err := tmpl.ExecuteTemplate(&buf, "oui", data); err != nil {
		return err
	}

	fout, err := os.Create(dst)
	if err != nil {
		return err
	}

	defer fout.Close()

	code, err := format.Source(buf.Bytes())
	if err != nil {
		return err
	}

	if _, err := fout.Write(code); err != nil {
		return err
	}

	return nil
}

func newTemplateData(r io.Reader) *templateData {
	var (
		entries     []entry
		vendors     []string
		vendorsFull []string
	)

	ouiMap := make(map[string]string)
	vendorMap := make(map[string]int)

	c := csv.NewReader(r)

	_, err := c.Read() // skip header
	if err != nil {
		panic(err)
	}

	id := 0
	for {
		record, err := c.Read()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			panic(err)
		}

		o := strings.ToLower(record[1])

		v := strings.TrimSpace(record[2])
		vf := strings.Join(strings.Fields(v), " ")
		vf = strings.ReplaceAll(vf, `"`, "")
		if IsUpper(v) {
			vf = caser.String(vf)
		}
		v = pattern.ReplaceAllString(v, "")
		v = sr.Replace(v)
		v = strings.Join(strings.Fields(v), " ")
		if IsUpper(v) {
			v = caser.String(v)
		}
		v = strings.TrimSpace(strings.ReplaceAll(v, "/", ""))

		if prev, ok := ouiMap[o]; ok { // 080030 is a known duplicate
			log.Printf("Warning %q:%q is already registered to %q", o, v, prev)
			continue
		}

		ouiMap[o] = v

		if _, ok := vendorMap[v]; !ok {
			vendors = append(vendors, v)
			vendorsFull = append(vendorsFull, vf)
			vendorMap[v] = id
			id++
		}

		entries = append(entries, entry{OUI: OUI(o), Vendor: v, VendorID: vendorMap[v]})
	}
	for k, v := range maps.All(genEthernetNumbersMap()) {
		if prev, ok := ouiMap[k]; ok {
			log.Printf("Warning %q:%q is already registered to %q", k, v, prev)
			continue
		}
		ouiMap[k] = v
		if _, ok := vendorMap[v]; !ok {
			vendors = append(vendors, v)
			vendorsFull = append(vendorsFull, v)
			vendorMap[v] = id
			id++
		}
		entries = append(entries, entry{OUI: OUI(k), Vendor: v, VendorID: vendorMap[v]})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].OUI.Int() < entries[j].OUI.Int()
	})

	return &templateData{
		Entries:     entries,
		Vendors:     vendors,
		VendorsFull: vendorsFull,
	}
}
