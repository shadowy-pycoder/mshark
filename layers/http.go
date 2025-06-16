package layers

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httputil"
)

var (
	protohttp10 = []byte("HTTP/1.0")
	protohttp11 = []byte("HTTP/1.1")
)

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
// port 80
type HTTPMessage struct {
	Request  *http.Request
	Response *http.Response
}

func (h *HTTPMessage) IsEmpty() bool {
	return h.Request == nil && h.Response == nil
}

func (h *HTTPMessage) String() string {
	m := ellipsis
	if h.Request != nil {
		m, _ = httputil.DumpRequest(h.Request, false)
		m = joinBytes(dash, bytes.TrimRight(bytes.TrimSuffix(bytes.Join(bytes.Split(m, crlf), lfd), crlf), slfd))
	} else if h.Response != nil {
		m, _ = httputil.DumpResponse(h.Response, false)
		m = joinBytes(dash, bytes.TrimRight(bytes.TrimSuffix(bytes.Join(bytes.Split(m, crlf), lfd), crlf), slfd))
	}
	return fmt.Sprintf(`%s
%s
`, h.Summary(), m)
}

func (h *HTTPMessage) Summary() string {
	m := fmt.Sprintf("HTTP Message: %s", contdata)
	if h.Request != nil {
		m = fmt.Sprintf("HTTP Request: %s %s%s%s %s Content-Length: %d",
			h.Request.Method, h.Request.Host, h.Request.URL.Path, h.Request.URL.RawQuery, h.Request.Proto, h.Request.ContentLength)
	} else if h.Response != nil {
		m = fmt.Sprintf("HTTP Response: %s %s Content-Length: %d",
			h.Response.Proto, h.Response.Status, h.Response.ContentLength)
	}
	return fmt.Sprintf("%s", m)
}

func (h *HTTPMessage) Parse(data []byte) error {

	if !bytes.Contains(data, protohttp10) && !bytes.Contains(data, protohttp11) {
		h.Request = nil
		h.Response = nil
		return nil
	}
	reader := bufio.NewReader(bytes.NewReader(data))
	if bytes.HasPrefix(data, protohttp11) || bytes.HasPrefix(data, protohttp10) {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			return err
		}
		h.Response = resp
		h.Request = nil
	} else {
		reader := bufio.NewReader(bytes.NewReader(data))
		req, err := http.ReadRequest(reader)
		if err != nil {
			return err
		}
		h.Request = req
		h.Response = nil
	}
	return nil
}

func (h *HTTPMessage) NextLayer() (layer string, payload []byte) { return }
