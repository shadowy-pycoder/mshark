package main

import (
	"fmt"
	"net"
	"os"

	"github.com/shadowy-pycoder/mshark/oui"
)

var app = "moui"

func root(args []string) error {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: moui <MAC address>\n")
		os.Exit(2)
	}
	mac, err := net.ParseMAC(args[0])
	if err != nil {
		return err
	}
	vendor := oui.VendorFromMAC(mac)
	if vendor != "" {
		fmt.Println(vendor)
	}
	vendor = oui.VendorWithMAC(mac)
	fmt.Println(vendor)
	return nil
}

func main() {
	if err := root(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", app, err)
		os.Exit(2)
	}
}
