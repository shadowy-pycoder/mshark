// Package mshark is a simple packet capture tool
package mshark

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/packet"
	"github.com/shadowy-pycoder/mshark/layers"
	"github.com/shadowy-pycoder/mshark/network"
)

var colorMap = map[int]string{ // TODO (shadowy-pycoder): add colors from shadowy-pycoder/colors
	0: "\033[37m",
	1: "\033[36m",
	2: "\033[32m",
	3: "\033[33m",
	4: "\033[35m",
}

var (
	packetDelimeter      = strings.Repeat("─", 66)
	packetDelimeterColor = "\033[37m" + packetDelimeter + "\033[0m"
	SupportedFormats     = []string{"stdout", "txt", "pcap", "pcapng"}
	errParseConfig       = fmt.Errorf(
		`failed parsing config. Example: "interface eth0;snaplen 65535;promisc true;timeout 10s;packet_count 100;packet_buffer 8192;expr ip proto tcp;exts stdout,txt,pcap,pcapng"`,
	)
)

var _ PacketWriter = &Writer{}

type PacketWriter interface {
	WritePacket(timestamp time.Time, data []byte) error
	io.Closer
	Name() string
}

type Config struct {
	Device       *net.Interface // The name of the network interface ("any" means listen on all interfaces).
	Snaplen      int            // The maximum length of each packet snapshot.
	Promisc      bool           // Promiscuous mode. This setting is ignored for "any" interface.
	Timeout      time.Duration  // The maximum deadline for new packet to arrive
	PacketCount  int            // The maximum number of packets to capture.
	PacketBuffer int            // The maximum size for packet buffer (Default: 8192)
	Expr         string         // BPF filter expression.
	Exts         ExtNames       // file formats to put packet capture
}

// NewConfig creates Config from a list of options separated by semicolon.
//
// Example: "interface eth0;snaplen 65535;promisc true;timeout 10s;packet_count 100;packet_buffer 8192;expr ip proto tcp;exts stdout,txt,pcap,pcapng".
// All fields in configuration string are optional.
func NewConfig(s string) (*Config, error) {
	c := &Config{}
	var promiscSet bool
	for opt := range strings.SplitSeq(strings.ToLower(s), ";") {
		keyval := strings.SplitN(strings.Trim(opt, " "), " ", 2)
		if len(keyval) < 2 {
			return nil, errParseConfig
		}
		key := keyval[0]
		val := keyval[1]
		switch key {
		case "interface":
			in, err := network.InterfaceByName(val)
			if err != nil {
				return nil, err
			}
			c.Device = in
		case "snaplen":
			sl, err := strconv.ParseUint(val, 10, 16)
			if err != nil {
				return nil, err
			}
			c.Snaplen = int(sl)
		case "promisc":
			switch val {
			case "true", "1":
				c.Promisc = true
			case "false", "0":
				c.Promisc = false
			default:
				return nil, fmt.Errorf("unknown value %q for %q", val, key)
			}
			promiscSet = true
		case "timeout":
			t, err := time.ParseDuration(val)
			if err != nil {
				return nil, err
			}
			c.Timeout = t
		case "packet_count":
			pc, err := strconv.Atoi(val)
			if err != nil {
				return nil, err
			}
			c.PacketCount = pc
		case "packet_buffer":
			pb, err := strconv.Atoi(val)
			if err != nil {
				return nil, err
			}
			c.PacketBuffer = pb
		case "expr":
			c.Expr = val
		case "exts":
			exts, err := NewExtNames(val)
			if err != nil {
				return nil, err
			}
			c.Exts = *exts
		default:
			return nil, errParseConfig
		}
	}
	if !c.Promisc && !promiscSet {
		c.Promisc = true
	}
	if c.Snaplen <= 0 {
		c.Snaplen = 65535
	}
	if c.PacketBuffer <= 0 {
		c.PacketBuffer = 8192
	}
	return c, nil
}

type ExtNames []string

func NewExtNames(exts string) (*ExtNames, error) {
	en := make(ExtNames, 0, 4)
	for ext := range strings.SplitSeq(exts, ",") {
		if !slices.Contains(SupportedFormats, ext) {
			return nil, fmt.Errorf("unsupported file format: %s", ext)
		}
		if !slices.Contains(en, ext) {
			en = append(en, ext)
		}
	}
	return &en, nil
}

func (en *ExtNames) MarshalText() ([]byte, error) {
	return nil, nil
}

func (en *ExtNames) UnmarshalText(b []byte) error {
	exts := *en
	for ext := range strings.SplitSeq(string(b), ",") {
		if !slices.Contains(exts, ext) && slices.Contains(SupportedFormats, ext) {
			exts = append(exts, ext)
		}
	}
	*en = exts
	return nil
}

type Writer struct {
	w       io.Writer
	packets uint64
	stdout  bool
	verbose bool
	closer  io.Closer
}

// NewWriter creates a new mshark Writer.
func NewWriter(w io.Writer, verbose bool) *Writer {
	var c io.Closer

	if w != os.Stdout {
		if closer, ok := w.(io.Closer); ok {
			c = closer
		}
	}
	return &Writer{
		w:       w,
		stdout:  w == os.Stdout,
		verbose: verbose,
		closer:  c,
	}
}

// printPacket prints a layer packet to the writer. If the writer is an instance of os.Stdout,
// the packet will be printed with color, based on the layerNum.
func (mw *Writer) printPacket(layer layers.Layer, layerNum int) {
	var packet string
	if mw.verbose {
		packet = layer.String()
	} else {
		packet = layer.Summary()
	}
	if mw.stdout {
		if color, ok := colorMap[layerNum]; ok {
			packet = color + packet + "\033[0m"
		}
	}
	fmt.Fprintln(mw.w, packet)
}

// WritePacket writes a packet to the writer, along with its timestamp.
//
// Timestamps are to be generated by the calling code.
func (mw *Writer) WritePacket(timestamp time.Time, data []byte) error {
	mw.packets++
	fmt.Fprintf(mw.w, "- Packet: %d Timestamp: %s\n", mw.packets, timestamp.Format("2006-01-02T15:04:05.000000-0700"))
	if mw.stdout {
		fmt.Fprintln(mw.w, packetDelimeterColor)
	} else {
		fmt.Fprintln(mw.w, packetDelimeter)
	}
	next := layers.GetLayer(layers.LayerETH)
	if next == nil {
		return nil
	}
	if err := next.Parse(data); err != nil {
		return err
	}
	var layerNum int
	mw.printPacket(next, layerNum)
	for {
		next = next.NextLayer()
		if next == nil {
			return nil
		}
		layerNum++
		mw.printPacket(next, layerNum)
	}
}

// WriteHeader writes a header to the writer.
//
// The header contains metadata about the capture, such as the interface name,
// snapshot length, promiscuous mode, timeout, number of packets, and BPF filter.
//
// The header is written in the following format:
//
//   - Interface: eth0
//   - Snapshot Length: 65535
//   - Promiscuous Mode: true
//   - Timeout: 5s
//   - Number of Packets: 0
//   - Packet Buffer Size: 8192
//   - BPF Filter: "ip proto tcp"
//   - Verbose: true
func (mw *Writer) WriteHeader(c *Config) error {
	_, err := fmt.Fprintf(
		mw.w, `- Interface: %s
- Snapshot Length: %d
- Promiscuous Mode: %v
- Timeout: %s
- Number of Packets: %d
- Packet Buffer Size: %d
- BPF Filter: %q
- Verbose: %v

`,
		c.Device.Name,
		c.Snaplen,
		c.Device.Name != "any" && c.Promisc,
		c.Timeout,
		c.PacketCount,
		c.PacketBuffer,
		c.Expr,
		mw.verbose,
	)
	return err
}

func (mw *Writer) Name() string {
	if mw.stdout {
		return "stdout"
	}
	return "txt"
}

func (mw *Writer) Close() error {
	if mw.closer != nil {
		return mw.closer.Close()
	}
	return nil
}

// OpenLive opens a live capture based on the given configuration and writes
// all captured packets to the given PacketWriters.
func OpenLive(conf *Config, pw ...PacketWriter) error {
	lc := &network.ListenConfig{Device: conf.Device, Promiscuous: &conf.Promisc, FilterExpr: conf.Expr}
	c, err := network.ListenPacket(lc)
	if err != nil {
		return err
	}
	return OpenLiveFromPacketConn(c, conf, pw...)
}

func OpenLiveFromPacketConn(conn net.PacketConn, conf *Config, pw ...PacketWriter) error {
	done := make(chan bool)

	c, ok := conn.(*packet.Conn)
	if !ok {
		return fmt.Errorf("failed creating packet connection")
	}
	defer func() {
		stats, err := c.Stats()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch stats: %v", err)
		} else {
			for _, w := range pw {
				if w, ok := w.(*Writer); ok && (w.Name() == "stdout" || w.Name() == "txt") {
					fmt.Fprintf(w.w, "- Packets: %d, Drops: %d, Freeze Queue Count: %d\n",
						stats.Packets, stats.Drops, stats.FreezeQueueCount)
					fmt.Fprintf(w.w, "- Packets Captured: %d\n", w.packets)
				}
			}
		}
		for _, w := range pw {
			w.Close()
		}
		// close Conn
		err = c.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed closing connection: %v", err)
		}
	}()

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt)
		<-quit
		c.SetDeadline(time.Now().Add(5 * time.Second))
		close(done)
	}()

	// number of packets
	count := max(0, conf.PacketCount)
	infinity := count == 0

	b := make([]byte, conf.Snaplen)
	packetQueue := make(chan []byte, conf.PacketBuffer)

	go func() {
		for {
			select {
			case <-done:
				return
			case packet, ok := <-packetQueue:
				if !ok {
					return
				}
				for _, w := range pw {
					w.WritePacket(time.Now().UTC(), packet)
				}
			}
		}
	}()

	for i := 0; infinity || i < count; i++ {
		select {
		case <-done:
			close(packetQueue)
			return nil
		default:
			if conf.Timeout > 0 {
				if err := c.SetDeadline(time.Now().Add(conf.Timeout)); err != nil {
					return fmt.Errorf("unable to set timeout: %v", err)
				}
			}
			n, _, err := c.ReadFrom(b)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					return nil
				}
				return fmt.Errorf("failed to read Ethernet frame: %v", err)
			}
			packetQueue <- append([]byte(nil), b[:n]...)
		}
	}
	return nil
}
