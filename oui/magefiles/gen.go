package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"go/format"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

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

`
var caser = cases.Title(language.English)

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
	Entries []entry
	Vendors []string
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
		entries []entry
		vendors []string
	)

	ouiMap := make(map[string]string)
	vendorMap := make(map[string]int)

	c := csv.NewReader(r)

	_, err := c.Read() // skip header
	if err != nil {
		panic(err)
	}

	for id := 0; ; {
		record, err := c.Read()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			panic(err)
		}

		o := strings.ToLower(record[1])

		v := strings.TrimSpace(record[2])
		v = pattern.ReplaceAllString(v, "")
		v = sr.Replace(v)
		v = strings.Join(strings.Fields(v), " ")
		v = caser.String(v)
		v = strings.TrimSpace(strings.ReplaceAll(v, "/", ""))

		if prev, ok := ouiMap[o]; ok { // 080030 is a known duplicate
			log.Printf("Warning %q:%q is already registered to %q", o, v, prev)
			continue
		}

		ouiMap[o] = v

		if _, ok := vendorMap[v]; !ok {
			vendors = append(vendors, v)
			vendorMap[v] = id
			id++
		}

		entries = append(entries, entry{OUI: OUI(o), Vendor: v, VendorID: vendorMap[v]})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].OUI.Int() < entries[j].OUI.Int()
	})

	return &templateData{
		Entries: entries,
		Vendors: vendors,
	}
}
