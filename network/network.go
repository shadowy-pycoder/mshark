// Package network provides utility functions to extract some data about network
package network

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/mdlayher/packet"
	"github.com/packetcap/go-pcap/filter"
	"golang.org/x/net/bpf"
)

const ETH_P_ALL int = 0x03

var (
	BroadcastMAC            = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	LoopbackMAC             = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	IPv6MulticastMAC        = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
	IPv6MulticastAllNodes   = netip.MustParseAddr("ff02::1")
	IPv6MulticastAllRouters = netip.MustParseAddr("ff02::2")
)

type ListenConfig struct {
	Device      *net.Interface // network interface which to bind to, if not specified default interface is used
	Protocol    int            // network protocol, defaults to ETH_P_ALL
	Promiscuous *bool          // enable or disable promiscuous mode
	FilterExpr  string         // packet filter expression like in tcpdump
}

func ListenPacket(conf *ListenConfig) (*packet.Conn, error) {
	packetcfg := packet.Config{}
	// setting up filter
	if conf.FilterExpr != "" {
		e := filter.NewExpression(conf.FilterExpr)
		f := e.Compile()
		instructions, err := f.Compile()
		if err != nil {
			return nil, fmt.Errorf("failed to compile filter into instructions: %v", err)
		}
		raw, err := bpf.Assemble(instructions)
		if err != nil {
			return nil, fmt.Errorf("bpf assembly failed: %v", err)
		}
		packetcfg.Filter = raw
	}
	if conf.Device == nil {
		var err error
		conf.Device, err = GetDefaultInterface()
		if err != nil {
			return nil, err
		}
	}
	if conf.Protocol == 0 {
		conf.Protocol = ETH_P_ALL
	}
	// opening connection
	c, err := packet.Listen(conf.Device, packet.Raw, conf.Protocol, &packetcfg)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("permission denied (try setting CAP_NET_RAW capability): %v", err)
		}
		return nil, fmt.Errorf("failed to listen: %v", err)
	}
	// setting promisc mode
	if conf.Promiscuous != nil {
		if err := c.SetPromiscuous(*conf.Promiscuous); err != nil {
			return nil, fmt.Errorf("unable to set promiscuous mode: %v", err)
		}
	}
	return c, nil
}

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

func DisplayInterfaces(includeAny bool) error {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 0, 2, ' ', tabwriter.TabIndent)
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %v", err)
	}
	fmt.Fprintln(w, "Index\tName\tFlags")
	if includeAny {
		fmt.Fprintln(w, "0\tany\tUP")
	}
	for _, iface := range ifaces {
		fmt.Fprintf(w, "%d\t%s\t%s\n", iface.Index, iface.Name, strings.ToUpper(iface.Flags.String()))
	}
	return w.Flush()
}

func GetDefaultInterface() (*net.Interface, error) {
	// https://gist.github.com/player0k/038afe3031ee8d0176839a7542c086a5?permalink_comment_id=4679125#gistcomment-4679125
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
			if strings.Contains(fields[0], "tun") || strings.Contains(fields[0], "lo") {
				continue
			}
			defaultInterface = fields[0]
			break
		}
	}
	return net.InterfaceByName(defaultInterface)
}

func GetDefaultInterfaceFromRoute() (*net.Interface, error) {
	cmd := exec.Command("sh", "-c", `ip -4 route get 8.8.8.8 | tr -d '\n'`)
	routeRaw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	routeFields := strings.Fields(string(routeRaw))
	for i, f := range routeFields {
		if f == "dev" && i+1 < len(routeFields) && routeFields[i+1] != "tun" && routeFields[i+1] != "lo" {
			return net.InterfaceByName(routeFields[i+1])
		}
	}
	return nil, fmt.Errorf("failed getting default interface from route")
}

func GetDefaultInterfaceFromRouteIPv6() (*net.Interface, error) {
	cmd := exec.Command("sh", "-c", `ip -6 route get 2001:4860:4860::8888  | tr -d '\n'`)
	routeRaw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	routeFields := strings.Fields(string(routeRaw))
	for i, f := range routeFields {
		if f == "dev" && i+1 < len(routeFields) && routeFields[i+1] != "tun" && routeFields[i+1] != "lo" {
			return net.InterfaceByName(routeFields[i+1])
		}
	}
	return nil, fmt.Errorf("failed getting default interface from route")
}

func GetHostIPv6GlobalUnicastFromRoute() (netip.Addr, error) {
	cmd := exec.Command("sh", "-c", `ip -6 route get 2001:4860:4860::8888  | tr -d '\n'`)
	routeRaw, err := cmd.Output()
	if err != nil {
		return netip.Addr{}, err
	}
	routeFields := strings.Fields(string(routeRaw))
	for i, f := range routeFields {
		if f == "src" && i+1 < len(routeFields) {
			ip, err := netip.ParseAddr(string(routeFields[i+1]))
			if err != nil {
				return netip.Addr{}, err
			}
			if !ip.IsValid() || !Is6(ip) || !ip.IsGlobalUnicast() {
				return netip.Addr{}, fmt.Errorf("failed getting host IPv6 global unicast address from route")
			}
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("failed getting host IPv6 global unicast address from route")
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
		if strings.Contains(dev, "tun") || strings.Contains(dev, "lo") {
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

func GetDefaultGatewayIPv6() (netip.Addr, error) {
	cmd := exec.Command("sh", "-c", `ip -6 route show ::/0 | awk '{print $3 " " $5}'`)
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
		if strings.Contains(dev, "tun") || strings.Contains(dev, "lo") {
			continue
		}
		ip, err := netip.ParseAddr(ipstr)
		if err != nil {
			continue
		}
		if !ip.IsValid() || !Is6(ip) {
			continue
		}
		return ip, nil
	}
	return netip.Addr{}, fmt.Errorf("gateway IPv6 not found ")
}

func GetDefaultGatewayIPv4FromRoute() (netip.Addr, error) {
	cmd := exec.Command("sh", "-c", `ip -4 route get 8.8.8.8 | awk '{print $3}' | tr -d '\n'`)
	ipstrRaw, err := cmd.Output()
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(string(ipstrRaw))
	if err != nil {
		return netip.Addr{}, err
	}
	if !ip.IsValid() || !ip.Is4() {
		return netip.Addr{}, fmt.Errorf("failed getting default gateway from route")
	}
	return ip, nil
}

func GetDefaultGatewayIPv6FromRoute() (netip.Addr, error) {
	cmd := exec.Command("sh", "-c", `ip -6 route get 2001:4860:4860::8888 | awk '{print $5}' | tr -d '\n'`)
	ipstrRaw, err := cmd.Output()
	if err != nil {
		return netip.Addr{}, err
	}
	ipstr := string(ipstrRaw)
	if ipstr == "" {
		return netip.Addr{}, fmt.Errorf("failed getting default gateway IPv6 from route")
	}
	ip, err := netip.ParseAddr(ipstr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed getting default gateway IPv6 from route: %v", err)
	}
	if !ip.IsValid() || !Is6(ip) {
		return netip.Addr{}, fmt.Errorf("failed getting default gateway IPv6 from route")
	}
	return ip, nil
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

func GetGatewayIPv6FromInterface(iface string) (netip.Addr, error) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ip -6 route show dev %s", iface))
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
			if !Is6(ip) {
				continue
			}
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("gateway IPv6 not found for %s", iface)
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

func GetIPv6LinkLocalUnicastPrefixFromInterface(iface *net.Interface) (netip.Prefix, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Prefix{}, err
	}
	for _, a := range addrs {
		ipPrefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			return netip.Prefix{}, err
		}
		if Is6(ipPrefix.Addr()) && ipPrefix.Addr().IsLinkLocalUnicast() {
			return ipPrefix, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("no IPv6 link local unicast prefix found")
}

func GetIPv6GlobalUnicastPrefixFromInterface(iface *net.Interface) (netip.Prefix, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Prefix{}, err
	}
	for _, a := range addrs {
		ipPrefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			return netip.Prefix{}, err
		}
		if Is6(ipPrefix.Addr()) && ipPrefix.Addr().IsGlobalUnicast() {
			return ipPrefix, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("no IPv6 global unicast prefix found")
}

func IsLocalAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	host = strings.ToLower(host)
	return strings.HasSuffix(host, ".local") || host == "localhost"
}

// AddrEqual compares two address strings and returns true if they are equal.
//
// It treats loopback and unspecified IPs as equivalent. Returns false in case of inequality or error.
func AddrEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	addr1, err := netip.ParseAddrPort(a)
	if err != nil {
		return false
	}
	addr2, err := netip.ParseAddrPort(b)
	if err != nil {
		return false
	}
	if addr1.Addr().IsLoopback() {
		if addr1.Addr().Is4In6() || addr1.Addr().Is4() {
			addr1 = netip.AddrPortFrom(netip.IPv4Unspecified(), addr1.Port())
		} else {
			addr1 = netip.AddrPortFrom(netip.IPv6Unspecified(), addr1.Port())
		}
	}
	if addr2.Addr().IsLoopback() {
		if addr2.Addr().Is4In6() || addr2.Addr().Is4() {
			addr2 = netip.AddrPortFrom(netip.IPv4Unspecified(), addr2.Port())
		} else {
			addr2 = netip.AddrPortFrom(netip.IPv6Unspecified(), addr2.Port())
		}
	}
	return addr1.Compare(addr2) == 0
}

// ParseAddrPort parses provided address value and tries to convert it to netip.AddrPort.
//
// If address contains no IP (e.g. "80" or ":443"), it uses defaultHost to form address.
func ParseAddrPort(v, defaultHost string) (netip.AddrPort, error) {
	if port, err := strconv.Atoi(strings.TrimPrefix(v, ":")); err == nil {
		if port < 0 || port > 65535 {
			return netip.AddrPort{}, fmt.Errorf("port is out of range")
		}
		defHost, err := netip.ParseAddr(defaultHost)
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(defHost, uint16(port)), nil
	}
	return netip.ParseAddrPort(v)
}

// Is6 reports whether ip is an IPv6 address, excluding IPv4-mapped IPv6 addresses.
func Is6(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.Is6() || ip.Is4In6() {
		return false
	}
	return true
}

func PrefixIsValid(prefix netip.Addr, length int) bool {
	// https://github.com/mdlayher/ndp/blob/6da62358a1b4654a411ae2eb4540936d9f361c1c/option.go#L184
	p := netip.PrefixFrom(prefix, length)
	if masked := p.Masked(); prefix != masked.Addr() {
		return false
	}
	return true
}

func GetSystemNameservers() ([]netip.Addr, error) {
	var fBytes []byte
	var err error
	fBytes, err = os.ReadFile("/run/systemd/resolve/resolv.conf")
	if err != nil {
		fBytes, err = os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
	}
	ns := make([]netip.Addr, 0, 3)
	for line := range strings.Lines(string(fBytes)) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		if !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() {
			continue
		}
		ns = append(ns, addr)
	}
	if len(ns) == 0 {
		return nil, fmt.Errorf("failed to find nameservers")
	}
	return ns, nil
}

// GetPromiscuous returns promiscuous mode bit value for given interface or -1 on error
func GetPromiscuous(iface string) int {
	flagsData, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/flags", iface))
	if err != nil {
		return -1
	}
	flags, err := strconv.ParseInt(strings.TrimRight(string(flagsData), "\n"), 0, 64)
	if err != nil {
		return -1
	}
	return int(flags & 0x100)
}

// SetPromiscuous enables or disables promiscuous mode for given interface
func SetPromiscuous(iface string, enable bool) error {
	onoff := "off"
	if enable {
		onoff = "on"
	}
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ip link set dev %s promisc %s", iface, onoff))
	return cmd.Run()
}

func PrettifyBytes(b int64) string {
	// https://stackoverflow.com/a/1094933/1333724
	bf := float64(b)
	for _, unit := range []string{"", "K", "M", "G", "T", "P", "E", "Z"} {
		if bf < 1000.0 {
			return fmt.Sprintf("%3.1f%sB", bf, unit)
		}
		bf /= 1000.0
	}
	return fmt.Sprintf("%.1fYB", bf)
}

// GetHostName performs the reverse DNS lookup for given address
func GetHostName(ip netip.Addr) (string, error) {
	ip = StripZone(ip)
	cmd := exec.Command("sh", "-c", fmt.Sprintf("dig -x %s +short +time=1 +tries=1", ip))
	domainBytes, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to perform reverse lookup for %s: %v", ip, err)
	}
	domain := strings.TrimRight(string(domainBytes), "\r\n.")
	if domain == "" {
		return "", fmt.Errorf("failed to perform reverse lookup for %s", ip)
	}
	return domain, nil
}

// StripZone removes zone from IPv6 address
func StripZone(ip netip.Addr) netip.Addr {
	if !Is6(ip) {
		return ip
	}
	return netip.AddrFrom16(ip.As16())
}

// GetIPv6Resolver returns first suitable IPv6 address from resolv.conf or Google IPv6 DNS as fallback
func GetIPv6Resolver(dev *net.Interface) *net.UDPAddr {
	if resolvers, err := GetSystemNameservers(); err == nil {
		for _, r := range resolvers {
			if Is6(r) {
				var zone string
				if r.IsLinkLocalUnicast() && dev != nil {
					zone = dev.Name
				}
				return &net.UDPAddr{IP: net.ParseIP(StripZone(r).String()), Port: 53, Zone: zone}
			}
		}
	}
	return &net.UDPAddr{IP: net.ParseIP("2001:4860:4860::8888"), Port: 53}
}

// BroadcastFromPrefix calculates broadcast address from IPv4 prefix.Addr
func BroadcastFromPrefix(prefix netip.Prefix) (netip.Addr, error) {
	if !prefix.IsValid() || prefix.Addr().Is6() {
		return netip.Addr{}, fmt.Errorf("only IPv4 addresses are supported")
	}
	prefixAddr := netip.AddrFrom4(prefix.Addr().As4()).AsSlice()
	netID := make([]byte, 4)
	binary.BigEndian.PutUint32(netID, binary.BigEndian.Uint32(prefixAddr)|uint32(0xffffffff>>prefix.Bits()))
	addr, ok := netip.AddrFromSlice(netID)
	if !ok {
		return netip.Addr{}, fmt.Errorf("failed parsing broadcast address")
	}
	return addr, nil
}
