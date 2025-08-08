package layers

import (
	"bufio"
	"bytes"
	"encoding/json"
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
		m = fmt.Sprintf(
			"HTTP Request: %s %s%s%s %s Content-Length: %d",
			h.Request.Method,
			h.Request.Host,
			h.Request.URL.Path,
			h.Request.URL.RawQuery,
			h.Request.Proto,
			h.Request.ContentLength,
		)
	} else if h.Response != nil {
		m = fmt.Sprintf("HTTP Response: %s %s Content-Length: %d",
			h.Response.Proto, h.Response.Status, h.Response.ContentLength)
	}
	return m
}

func (h *HTTPMessage) Parse(data []byte) error {
	buf := make([]byte, 0, len(data))
	buf = append(buf, data...)
	if !bytes.Contains(buf, protohttp10) && !bytes.Contains(buf, protohttp11) {
		h.Request = nil
		h.Response = nil
		return nil
	}
	reader := bufio.NewReader(bytes.NewReader(buf))
	if bytes.HasPrefix(buf, protohttp11) || bytes.HasPrefix(buf, protohttp10) {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			return err
		}
		h.Response = resp
		h.Request = nil
	} else {
		reader := bufio.NewReader(bytes.NewReader(buf))
		req, err := http.ReadRequest(reader)
		if err != nil {
			return err
		}
		h.Request = req
		h.Response = nil
	}
	return nil
}

func (h *HTTPMessage) NextLayer() Layer { return nil }
func (h *HTTPMessage) Name() string     { return "HTTP" }

type HTTPRequestWrapper struct {
	Request HTTPRequest `json:"http_request"`
}

type HTTPRequest struct {
	Host          string      `json:"host,omitempty"`
	URI           string      `json:"uri,omitempty"`
	Method        string      `json:"method,omitempty"`
	Proto         string      `json:"proto,omitempty"`
	ContentLength int         `json:"content-length,omitempty"`
	Header        http.Header `json:"header,omitempty"`
}

type HTTPResponseWrapper struct {
	Response HTTPResponse `json:"http_response"`
}

type HTTPResponse struct {
	Proto         string      `json:"proto,omitempty"`
	Status        string      `json:"status,omitempty"`
	ContentLength int         `json:"content-length,omitempty"`
	Header        http.Header `json:"header,omitempty"`
}

func (h *HTTPMessage) MarshalJSON() ([]byte, error) {
	if h.Request != nil {
		return json.Marshal(&HTTPRequestWrapper{Request: HTTPRequest{
			Host:          h.Request.Host,
			URI:           h.Request.RequestURI,
			Method:        h.Request.Method,
			Proto:         h.Request.Proto,
			ContentLength: int(h.Request.ContentLength),
			Header:        h.Request.Header,
		}})
	} else if h.Response != nil {
		return json.Marshal(&HTTPResponseWrapper{Response: HTTPResponse{
			Proto:         h.Response.Proto,
			Status:        h.Response.Status,
			ContentLength: int(h.Response.ContentLength),
			Header:        h.Response.Header,
		}})
	}
	return nil, fmt.Errorf("both request and response are empty")
}
