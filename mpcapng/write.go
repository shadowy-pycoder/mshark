// Package mpcapng implements PCAP Next Generation (pcapng) Capture File Format
package mpcapng

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os/exec"
	"time"

	"github.com/shadowy-pycoder/mshark/native"
)

// https://pcapng.com/
const (
	shbBlockType    uint32 = 0x0a0d0d0a
	byteOrderMagic  uint32 = 0x1a2b3c4d
	versionMajor    uint16 = 0x0001
	versionMinor    uint16 = 0x0000
	sectionLen      uint64 = 0xffffffffffffffff
	shbHardwareCode uint16 = 0x0002
	shbOSCode       uint16 = 0x0003
	shbUserAppCode  uint16 = 0x0004
	idbBlockType    uint32 = 0x00000001
	linkType        uint16 = 1
	reserved        uint16 = 0
	timeRes         uint8  = 0x03
	ifNameCode      uint16 = 0x0002
	ifDescCode      uint16 = 0x0003
	ifMACCode       uint16 = 0x0006
	ifTSResCode     uint16 = 0x0009
	ifFilterCode    uint16 = 0x000b
	ifOSCode        uint16 = 0x000c
	epbBlockType    uint32 = 0x00000006
	interfaceID     uint32 = 0x00000000 // only support one IDB
)

var (
	nativeEndian binary.ByteOrder = native.Endian
	zero         []byte           = []byte{0}
)

type Writer struct {
	w      io.Writer
	closer io.Closer
}

// NewWriter creates a new PCAPNG Writer that writes to the given io.Writer.
func NewWriter(w io.Writer) *Writer {
	var c io.Closer

	if closer, ok := w.(io.Closer); ok {
		c = closer
	}
	return &Writer{w: w, closer: c}
}

// WriteHeader writes a Section Header Block (SHB) and an Interface Description Block (IDB)
// to the pcapng file.
//
// The SHB contains metadata about the capture, and the IDB describes the interface
// that the packets were captured on.
func (pw *Writer) WriteHeader(app string, in *net.Interface, expr string, snaplen int) error {
	if err := pw.writeSHB(app); err != nil {
		return err
	}
	if err := pw.writeIDB(in, expr, snaplen); err != nil {
		return err
	}
	return nil
}

// writeSHB writes a Section Header Block (SHB) to the  file.
//
// https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html#section_shb
func (pw *Writer) writeSHB(app string) error {
	options, err := pw.writeShbOptions(app)
	if err != nil {
		return err
	}
	blockLen := 4 + 4 + 4 + 2 + 2 + 8 + len(options) + 4
	buf := bytes.NewBuffer(make([]byte, 0, blockLen))
	binary.Write(buf, nativeEndian, shbBlockType)
	binary.Write(buf, nativeEndian, uint32(blockLen))
	binary.Write(buf, nativeEndian, byteOrderMagic)
	binary.Write(buf, nativeEndian, versionMajor)
	binary.Write(buf, nativeEndian, versionMinor)
	binary.Write(buf, nativeEndian, sectionLen)
	binary.Write(buf, nativeEndian, options)
	binary.Write(buf, nativeEndian, uint32(blockLen))
	_, err = pw.w.Write(buf.Bytes())
	return err
}

func pad(size int) int {
	return (4 - (size & 3)) & 3
}

func gethwinfo() ([]byte, []byte, error) {
	hwinfo, err := exec.Command("sh", "-c", "lscpu | grep 'Model name' | cut -f 2 -d ':' | awk '{$1=$1}1'").Output()
	if err != nil {
		return nil, nil, err
	}
	hwinfo = bytes.TrimRight(hwinfo, "\n")
	osinfo, err := exec.Command("sh", "-c", "uname -orm").Output()
	if err != nil {
		return nil, nil, err
	}
	osinfo = bytes.TrimRight(osinfo, "\n")
	return hwinfo, osinfo, nil
}

func (pw *Writer) writeShbOptions(app string) ([]byte, error) {
	hwinfo, osinfo, err := gethwinfo()
	if err != nil {
		return nil, err
	}
	hwLen := len(hwinfo)
	hPad := pad(len(hwinfo))
	osLen := len(osinfo)
	osPad := pad(len(osinfo))
	appLen := len(app)
	userPad := pad(len(app))
	buflen := (2 + // shb_hardware code
		2 + // shb_hardware length
		hwLen + // shb_hardware
		hPad + // padding
		2 + // shb_os code
		2 + // shb_os length
		osLen + // shb_os
		osPad + // padding
		2 + // shb_userappl code
		2 + // shb_userappl length
		appLen + // shb_userappl
		userPad + // padding
		2 + // opt_endofopt
		2) // opt_endofopt length (must be 0)
	buf := bytes.NewBuffer(make([]byte, 0, buflen))
	binary.Write(buf, nativeEndian, shbHardwareCode)
	binary.Write(buf, nativeEndian, uint16(hwLen))
	binary.Write(buf, nativeEndian, hwinfo)
	buf.Write(bytes.Repeat(zero, hPad))
	binary.Write(buf, nativeEndian, shbOSCode)
	binary.Write(buf, nativeEndian, uint16(osLen))
	binary.Write(buf, nativeEndian, osinfo)
	buf.Write(bytes.Repeat(zero, osPad))
	binary.Write(buf, nativeEndian, shbUserAppCode)
	binary.Write(buf, nativeEndian, uint16(appLen))
	binary.Write(buf, nativeEndian, []byte(app))
	buf.Write(bytes.Repeat(zero, userPad))
	buf.Write(bytes.Repeat(zero, 4))
	return buf.Bytes(), nil
}

// writeIDB writes an Interface Description Block (IDB) to the  file.
//
// https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html#name-interface-description-block
func (pw *Writer) writeIDB(in *net.Interface, expr string, snaplen int) error {
	options, err := pw.writeIdbOptions(in, expr)
	if err != nil {
		return err
	}
	blockLen := 4 + 4 + 2 + 2 + 4 + len(options) + 4
	buf := bytes.NewBuffer(make([]byte, 0, blockLen))
	binary.Write(buf, nativeEndian, idbBlockType)
	binary.Write(buf, nativeEndian, uint32(blockLen))
	binary.Write(buf, nativeEndian, linkType)
	binary.Write(buf, nativeEndian, reserved)
	binary.Write(buf, nativeEndian, uint32(snaplen))
	binary.Write(buf, nativeEndian, options)
	binary.Write(buf, nativeEndian, uint32(blockLen))
	_, err = pw.w.Write(buf.Bytes())
	return err
}

func (pw *Writer) writeIdbOptions(in *net.Interface, expr string) ([]byte, error) {
	_, osinfo, err := gethwinfo()
	if err != nil {
		return nil, err
	}
	osLen := len(osinfo)
	osPad := pad(len(osinfo))
	ifName := in.Name
	ifNameLen := len(ifName)
	ifNamePad := pad(ifNameLen)
	exprLen := len(expr) + 1
	exprPad := pad(exprLen)
	buflen := (2 + // if_name code
		2 + // if_name length
		ifNameLen + // if_name
		ifNamePad + // padding
		2 + // if_description code
		2 + // if_description length
		ifNameLen + // if_description
		ifNamePad + // padding
		2 + // if_MACaddr code
		2 + // if_MACaddr length
		6 + // MAC address
		2 + // padding
		2 + // if_tsresol code
		2 + // if_tsresol length
		1 + // if_tsresol
		3 + // padding
		2 + // if_filter code
		2 + // if_filter length
		exprLen + // if_filter
		exprPad + // padding
		2 + // if_os code
		2 + // if_os length
		osLen + // if_os
		osPad + // padding
		2 + // opt_endofopt
		2) // opt_endofopt length (must be 0)
	buf := bytes.NewBuffer(make([]byte, 0, buflen))
	binary.Write(buf, nativeEndian, ifNameCode)
	binary.Write(buf, nativeEndian, uint16(ifNameLen))
	binary.Write(buf, nativeEndian, []byte(ifName))
	buf.Write(bytes.Repeat(zero, ifNamePad))
	binary.Write(buf, nativeEndian, ifDescCode)
	binary.Write(buf, nativeEndian, uint16(ifNameLen))
	binary.Write(buf, nativeEndian, []byte(ifName))
	buf.Write(bytes.Repeat(zero, ifNamePad))
	binary.Write(buf, nativeEndian, ifMACCode)
	binary.Write(buf, nativeEndian, uint16(6))
	if in.Name == "any" || in.Index == 0 {
		buf.Write(bytes.Repeat(zero, 6))
	} else {
		binary.Write(buf, nativeEndian, in.HardwareAddr)
	}
	buf.Write(bytes.Repeat(zero, 2))
	binary.Write(buf, nativeEndian, ifTSResCode)
	binary.Write(buf, nativeEndian, uint16(1))
	binary.Write(buf, nativeEndian, timeRes)
	buf.Write(bytes.Repeat(zero, 3))
	binary.Write(buf, nativeEndian, ifFilterCode)
	binary.Write(buf, nativeEndian, uint16(exprLen))
	buf.Write(bytes.Repeat(zero, 1))
	binary.Write(buf, nativeEndian, []byte(expr))
	buf.Write(bytes.Repeat(zero, exprPad))
	binary.Write(buf, nativeEndian, ifOSCode)
	binary.Write(buf, nativeEndian, uint16(osLen))
	binary.Write(buf, nativeEndian, osinfo)
	buf.Write(bytes.Repeat(zero, osPad))
	buf.Write(bytes.Repeat(zero, 4))
	return buf.Bytes(), nil
}

// WritePacket writes an Enhanced Packet Block (EPB) to the  file.
//
// https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html#name-enhanced-packet-block
func (pw *Writer) WritePacket(timestamp time.Time, data []byte) error {
	packetLen := len(data)
	padLen := pad(packetLen)
	blockLen := 4 + 4 + 4 + 4 + 4 + 4 + 4 + packetLen + padLen + 4
	binary.Write(pw.w, nativeEndian, epbBlockType)
	binary.Write(pw.w, nativeEndian, uint32(blockLen))
	binary.Write(pw.w, nativeEndian, interfaceID)
	msecs := uint64(timestamp.UnixMilli())
	binary.Write(pw.w, nativeEndian, uint32(msecs>>32))
	binary.Write(pw.w, nativeEndian, uint32(msecs&(1<<32-1)))
	binary.Write(pw.w, nativeEndian, uint32(packetLen))
	binary.Write(pw.w, nativeEndian, uint32(packetLen))
	if _, err := pw.w.Write(data); err != nil {
		return err
	}
	pw.w.Write(bytes.Repeat(zero, padLen))
	binary.Write(pw.w, nativeEndian, uint32(blockLen))
	return nil
}

func (pw *Writer) Name() string {
	return "pcapng"
}

func (pw *Writer) Close() error {
	return pw.closer.Close()
}
