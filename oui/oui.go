// Package oui provides functions to generate hardware vendor names from hardware addresses
package oui

import (
	"net"
	"strings"
)

//go:generate mage -v build
func Vendor(s string) string {
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
	return vendors[id]
}

// VendorFromMAC returns the hardware vendor of a net.HardwareAddr.
func VendorFromMAC(hw net.HardwareAddr) string {
	return Vendor(hw.String())
}

// VendorWithMAC concatenates vendor with MAC address (e.g. Next_01:02:03)
func VendorWithMAC(hw net.HardwareAddr) string {
	vendor := Vendor(hw.String())
	if vendor != "" {
		vendor = strings.ReplaceAll(vendor, " ", "_")
		return vendor + "_" + hw.String()[9:]
	}
	return hw.String()
}
