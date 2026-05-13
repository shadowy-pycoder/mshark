// Package mpcap implements PCAP Capture File Format
package mpcap

import (
	"fmt"
	"io"
	"time"

	"github.com/shadowy-pycoder/mshark/native"
)

// https://wiki.wireshark.org/Development/LibpcapFileFormat/
const (
	magicNumber  uint32 = 0xa1b2c3d4
	versionMajor uint16 = 2
	versionMinor uint16 = 4
	thisZone     int32  = 0
	sigFigs      uint32 = 0
	network      uint32 = 1
)

var nativeEndian = native.Endian

type Writer struct {
	w      io.Writer
	buf    [16]byte
	closer io.Closer
}

// NewWriter creates a new PCAP Writer that writes to the given io.Writer.
func NewWriter(w io.Writer) *Writer {
	var c io.Closer

	if closer, ok := w.(io.Closer); ok {
		c = closer
	}
	return &Writer{w: w, closer: c}
}

// WriteHeader writes a global header block to the pcap file.
//
// The global header block contains metadata about the capture, such as the
// timestamp format and the maximum packet length.
//
// See https://wiki.wireshark.org/Development/LibpcapFileFormat for more
// information about the pcap file format.
func (pw *Writer) WriteHeader(snaplen int) error {
	var buf [24]byte
	nativeEndian.PutUint32(buf[0:4], magicNumber)
	nativeEndian.PutUint16(buf[4:6], versionMajor)
	nativeEndian.PutUint16(buf[6:8], versionMinor)
	nativeEndian.PutUint32(buf[8:12], uint32(thisZone))
	nativeEndian.PutUint32(buf[12:16], sigFigs)
	nativeEndian.PutUint32(buf[16:20], uint32(snaplen))
	nativeEndian.PutUint32(buf[20:24], network)
	_, err := pw.w.Write(buf[:])
	return err
}

func (pw *Writer) writePacketHeader(timestamp time.Time, packetLen int) error {
	secs := timestamp.Unix()
	msecs := timestamp.Nanosecond() / 1e6
	nativeEndian.PutUint32(pw.buf[0:4], uint32(secs))
	nativeEndian.PutUint32(pw.buf[4:8], uint32(msecs))
	nativeEndian.PutUint32(pw.buf[8:12], uint32(packetLen))
	nativeEndian.PutUint32(pw.buf[12:16], uint32(packetLen))
	_, err := pw.w.Write(pw.buf[:])
	return err
}

// WritePacket writes a packet to the pcap file.
//
// The packet is written as a packet header plus the packet data.
// The timestamp is written as the number of seconds since the epoch,
// and the packet data is written as a sequence of bytes of the length
// specified in the packet header.
//
// See https://wiki.wireshark.org/Development/LibpcapFileFormat for more
// information about the pcap file format.
func (pw *Writer) WritePacket(timestamp time.Time, data []byte) error {
	if err := pw.writePacketHeader(timestamp, len(data)); err != nil {
		return fmt.Errorf("error writing packet header: %v", err)
	}
	_, err := pw.w.Write(data)
	return err
}

func (pw *Writer) Name() string {
	return "pcap"
}

func (pw *Writer) Close() error {
	return pw.closer.Close()
}
