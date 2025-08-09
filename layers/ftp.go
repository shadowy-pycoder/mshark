package layers

import (
	"bytes"
	"fmt"
)

type FTPMessage struct {
	summary []byte
	data    []byte
}

func (f *FTPMessage) String() string {
	return fmt.Sprintf(`%s
%s
`, f.Summary(), f.data)
}

func (f *FTPMessage) Summary() string {
	return fmt.Sprintf("FTP Message: %s", f.summary)
}

func (f *FTPMessage) Parse(data []byte) error {
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	f.summary = nil
	f.data = nil
	sp := bytes.Split(buf, crlf)
	lsp := len(sp)
	switch {
	case lsp > 2:
		f.summary = bytes.Join(sp[:2], bspace)
		sp[0] = joinBytes(dash, sp[0])
		f.data = bytes.TrimSuffix(bytes.TrimSuffix(bytes.Join(sp, lfd), dash), lf)
	case lsp > 1:
		f.summary = sp[0]
		sp[0] = joinBytes(dash, sp[0])
		f.data = bytes.TrimSuffix(bytes.TrimSuffix(bytes.Join(sp, lfd), dash), lf)
	default:
	}
	return nil
}

func (f *FTPMessage) NextLayer() Layer { return nil }
func (f *FTPMessage) Name() LayerName  { return LayerFTP }
