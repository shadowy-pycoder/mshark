// Package network provides utility functions to extract some data about network
package network

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
)

var (
	BroadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	LoopbackMAC  = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

// InterfaceByName returns the interface specified by name.
func InterfaceByName(name string) (*net.Interface, error) {
	var (
		in  *net.Interface
		err error
	)
	if name == "any" {
		in = &net.Interface{Index: 0, Name: "any"}
	} else {
		in, err = net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("unknown interface %s: %v", name, err)
		}
		ok := true &&
			// Look for an Ethernet interface.
			len(in.HardwareAddr) == 6 &&
			// Look for up, multicast, broadcast.
			in.Flags&(net.FlagUp|net.FlagMulticast|net.FlagBroadcast) != 0
		if !ok {
			return nil, fmt.Errorf("interface %s is not up", name)
		}
	}
	return in, nil
}

func DisplayInterfaces() error {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 0, 2, ' ', tabwriter.TabIndent)
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %v", err)
	}
	fmt.Fprintln(w, "Index\tName\tFlags")
	fmt.Fprintln(w, "0\tany\tUP")
	for _, iface := range ifaces {
		fmt.Fprintf(w, "%d\t%s\t%s\n", iface.Index, iface.Name, strings.ToUpper(iface.Flags.String()))
	}
	return w.Flush()
}

func GetDefaultInterface() (*net.Interface, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	defaultInterface := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "00000000" {
			if strings.Contains(fields[0], "tun") {
				continue
			}
			defaultInterface = fields[0]
			break
		}
	}
	return net.InterfaceByName(defaultInterface)
}

func GetDefaultGatewayIPv4() (netip.Addr, error) {
	cmd := exec.Command("sh", "-c", `ip -4 route show 0.0.0.0/0 | awk '{print $3 " " $5}'`)
	ipdevRaw, err := cmd.Output()
	if err != nil {
		return netip.Addr{}, err
	}
	for line := range strings.SplitSeq(strings.TrimRight(string(ipdevRaw), "\n"), "\n") {
		ipdev := strings.Fields(line)
		if len(ipdev) < 2 {
			continue
		}
		ipstr := ipdev[0]
		dev := ipdev[1]
		if strings.Contains(dev, "tun") {
			continue
		}
		ip, err := netip.ParseAddr(ipstr)
		if err != nil {
			continue
		}
		if !ip.IsValid() || !ip.Is4() {
			continue
		}
		return ip, nil
	}
	return netip.Addr{}, fmt.Errorf("gateway IPv4 not found ")
}

func GetGatewayIPv4FromInterface(iface string) (netip.Addr, error) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ip -4 route show dev %s", iface))
	routes, err := cmd.Output()
	if err != nil {
		return netip.Addr{}, err
	}
	for line := range strings.Lines(string(routes)) {
		fields := strings.Fields(line)
		if len(fields) > 2 && fields[1] == "via" {
			ip, err := netip.ParseAddr(fields[2])
			if err != nil {
				continue
			}
			if !ip.Is4() {
				continue
			}
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("gateway IPv4 not found for %s", iface)
}

func GetIPv4PrefixFromInterface(iface *net.Interface) (netip.Prefix, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Prefix{}, err
	}
	for _, a := range addrs {
		ipPrefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			return netip.Prefix{}, err
		}
		if ipPrefix.Addr().Is4() {
			return ipPrefix, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("no IPv4 prefix found")
}
