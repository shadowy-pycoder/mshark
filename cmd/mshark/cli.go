package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	ms "github.com/shadowy-pycoder/mshark"
	"github.com/shadowy-pycoder/mshark/mpcap"
	"github.com/shadowy-pycoder/mshark/mpcapng"
	"github.com/shadowy-pycoder/mshark/network"
)

const app string = "mshark"

const usagePrefix string = `                ______   __                            __
               /      \ |  \                          |  \
 ______ ____  |  $$$$$$\| $$____    ______    ______  | $$   __
|      \    \ | $$___\$$| $$    \  |      \  /      \ | $$  /  \
| $$$$$$\$$$$\ \$$    \ | $$$$$$$\  \$$$$$$\|  $$$$$$\| $$_/  $$
| $$ | $$ | $$ _\$$$$$$\| $$  | $$ /      $$| $$   \$$| $$   $$
| $$ | $$ | $$|  \__| $$| $$  | $$|  $$$$$$$| $$      | $$$$$$\
| $$ | $$ | $$ \$$    $$| $$  | $$ \$$    $$| $$      | $$  \$$\
 \$$  \$$  \$$  \$$$$$$  \$$   \$$  \$$$$$$$ \$$       \$$   \$$

Packet Capture Tool by shadowy-pycoder

GitHub: https://github.com/shadowy-pycoder/mshark
Codeberg: https://codeberg.org/shadowy-pycoder/mshark

Usage: mshark [OPTIONS]
Options:
  -h    Show this help message and exit.
`

var (
	_ ms.PacketWriter = &mpcap.Writer{}
	_ ms.PacketWriter = &mpcapng.Writer{}
)

func createFile(app, ext string) (*os.File, error) {
	path := fmt.Sprintf("./%s_%s.%s", app, time.Now().UTC().Format("20060102_150405"), ext)
	f, err := os.OpenFile(filepath.FromSlash(path), os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	return f, nil
}

func root(args []string) error {
	conf := ms.Config{}

	flags := flag.NewFlagSet(app, flag.ExitOnError)
	iface := flags.String("i", "any", "The name of the network interface. Example: eth0")
	snaplen := flags.Int("s", 0, "The maximum length of each packet snapshot. Defaults to 65535.")
	flags.BoolFunc(
		"p",
		`Promiscuous mode. This setting is ignored for "any" interface. Defaults to false.`,
		func(flagValue string) error {
			conf.Promisc = true
			return nil
		},
	)
	flags.DurationVar(&conf.Timeout, "t", 0, "The maximum deadline for capture process. Example: 5s")
	flags.IntVar(&conf.PacketCount, "c", 0, "The maximum number of packets to capture.")
	packetBuffer := flags.Int("b", 8192, "The maximum size of packet queue.")
	flags.StringVar(&conf.Expr, "e", "", `BPF filter expression. Example: "ip proto tcp".`)
	flags.BoolFunc("D", "Display list of interfaces and exit.", func(flagValue string) error {
		if err := network.DisplayInterfaces(true); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", app, err)
			os.Exit(2)
		}
		os.Exit(0)
		return nil
	})
	var verbose bool
	flags.BoolFunc("v", "Display full packet info when capturing to stdout or txt.", func(flagValue string) error {
		verbose = true
		return nil
	})
	flags.TextVar(&conf.Exts, "f", &conf.Exts, "File extension(s) to write captured data. Supported formats: stdout, txt, pcap, pcapng")

	flags.Usage = func() {
		fmt.Print(usagePrefix)
		flags.PrintDefaults()
	}
	flags.BoolFunc("V", "Show version and build information", func(flagValue string) error {
		fmt.Printf("%s (built for %s %s with %s)\n", ms.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		os.Exit(0)
		return nil
	})

	if err := flags.Parse(args); err != nil {
		return err
	}

	// getting network interface from the provided name
	in, err := network.InterfaceByName(*iface)
	if err != nil {
		return err
	}
	conf.Device = in

	// checking snaplen
	if *snaplen <= 0 || *snaplen > 65535 {
		*snaplen = 65535
	}
	conf.Snaplen = *snaplen

	if *packetBuffer <= 0 {
		*packetBuffer = 8192
	}
	conf.PacketBuffer = *packetBuffer

	// creating writers and writing headers depending on a file extension
	var pw []ms.PacketWriter
	if len(conf.Exts) != 0 {
		for _, ext := range conf.Exts {
			switch ext {
			case "stdout":
				w := ms.NewWriter(os.Stdout, verbose)
				if err := w.WriteHeader(&conf); err != nil {
					w.Close()
					return err
				}
				pw = append(pw, w)
			case "txt":
				f, err := createFile(app, ext)
				if err != nil {
					return err
				}
				w := ms.NewWriter(f, verbose)
				if err := w.WriteHeader(&conf); err != nil {
					w.Close()
					return err
				}
				pw = append(pw, w)
			case "pcap":
				f, err := createFile(app, ext)
				if err != nil {
					return err
				}
				w := mpcap.NewWriter(f)
				if err := w.WriteHeader(conf.Snaplen); err != nil {
					w.Close()
					return err
				}
				pw = append(pw, w)
			case "pcapng":
				f, err := createFile(app, ext)
				if err != nil {
					return err
				}
				w := mpcapng.NewWriter(f)
				if err := w.WriteHeader(app, conf.Device, conf.Expr, conf.Snaplen); err != nil {
					w.Close()
					return err
				}
				pw = append(pw, w)
			default:
				// unreachable
				return fmt.Errorf("unsupported file format: %s", ext)
			}
		}
	} else {
		w := ms.NewWriter(os.Stdout, verbose)
		if err := w.WriteHeader(&conf); err != nil {
			w.Close()
			return err
		}
		pw = append(pw, w)
	}
	return ms.OpenLive(&conf, pw...)
}
