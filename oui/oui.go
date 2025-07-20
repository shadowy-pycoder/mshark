// Package oui provides functions to generate hardware vendor names from hardware addresses
package oui

import (
	"bytes"
	"net"
	"strconv"
	"strings"
)

var (
	BroadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	LoopbackMAC  = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

func outMulticastRange(hw string) bool {
	s := strings.ReplaceAll(hw[9:], ":", "")
	n, err := strconv.ParseInt(s, 16, 64)
	if err != nil || n > 0x7fffff {
		return true
	}
	return false
}

//go:generate mage -v build
func Vendor(s string, full bool) string {
	s = strings.ReplaceAll(s, ":", "")
	switch {
	case len(s) < 6:
		return ""
	case len(s) > 6:
		s = s[0:6]
	}
	s = strings.ToLower(s)
	id, ok := ouis[s]
	if !ok {
		return ""
	}
	if id > len(vendors) {
		return ""
	}
	if full {
		return vendorsFull[id]
	}
	return vendors[id]
}

// VendorFromMAC returns the hardware vendor (full name) of a net.HardwareAddr.
func VendorFromMAC(hw net.HardwareAddr) string {
	vendor := Vendor(hw.String(), true)
	if vendor == "IPv4 Multicast" && outMulticastRange(hw.String()) {
		return ""
	}
	return vendor
}

// VendorWithMAC concatenates vendor with MAC address (e.g. Next_01:02:03).
//
// If vendor is not found returns MAC address
func VendorWithMAC(hw net.HardwareAddr) string {
	if bytes.Equal(BroadcastMAC, hw) {
		return "Broadcast_" + hw.String()[9:]
	}
	if bytes.Equal(LoopbackMAC, hw) {
		return "Loopback_" + hw.String()[9:]
	}
	vendor := Vendor(hw.String(), false)
	if vendor != "" {
		if vendor == "IPv4 Multicast" && outMulticastRange(hw.String()) {
			return hw.String()
		}
		vendor = strings.ReplaceAll(vendor, " ", "_")
		return vendor + "_" + hw.String()[9:]
	}
	return hw.String()
}
