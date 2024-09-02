package layers

import "fmt"

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
// port 80
type HTTPMessage struct {
	payload string
}

func (h *HTTPMessage) String() string {
	return fmt.Sprintf(`%s
%s`, h.Summary(), h.payload)
}
func (h *HTTPMessage) Summary() string {
	return fmt.Sprint("HTTP Message:")
}

func (h *HTTPMessage) Parse(data []byte) error {
	h.payload = bytesToStr(data)
	return nil
}

func (h *HTTPMessage) NextLayer() (string, []byte) {
	return "", nil
}
