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
	if !checkFTP(buf) {
		return fmt.Errorf("malformed ftp message")
	}
	sp := bytes.Split(buf, crlf)
	lsp := len(sp)
	switch {
	case lsp > 2:
		f.summary = bytes.TrimSpace(bytes.Join(sp[:2], bspace))
		sp[0] = joinBytes(dash, sp[0])
		f.data = bytes.TrimSpace(bytes.TrimSuffix(bytes.TrimSuffix(bytes.Join(sp, lfd), dash), lf))
	case lsp > 1:
		f.summary = bytes.TrimSpace(sp[0])
		sp[0] = joinBytes(dash, sp[0])
		f.data = bytes.TrimSpace(bytes.TrimSuffix(bytes.TrimSuffix(bytes.Join(sp, lfd), dash), lf))
	default:
		return fmt.Errorf("failed parsing FTP message")
	}
	if len(f.summary) == 0 || len(f.data) == 0 {
		return fmt.Errorf("failed parsing FTP message")
	}
	return nil
}

func (f *FTPMessage) NextLayer() Layer { return nil }
func (f *FTPMessage) Name() LayerName  { return LayerFTP }

func checkFTP(data []byte) bool {
	return (len(data) >= 4 && isDigit(data[0]) && isDigit(data[1]) &&
		isDigit(data[2]) && (data[3] == ' ' || data[3] == '-')) ||
		(len(data) >= 3 && isUpper(data[0]) && isUpper(data[1]) && isUpper(data[2]))
}
