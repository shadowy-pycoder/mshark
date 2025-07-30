package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"time"

	"github.com/rs/zerolog"
	"github.com/shadowy-pycoder/colors"
	"github.com/shadowy-pycoder/mshark/arpspoof"
	"github.com/shadowy-pycoder/mshark/network"
)

var (
	app           = "marpspoof"
	ipPortPattern = regexp.MustCompile(
		`\b(?:\d{1,3}\.){3}\d{1,3}(?::(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4}))?\b`,
	)
	macPattern = regexp.MustCompile(`(?i)([a-z0-9_]+_[0-9a-f]{2}(?::[0-9a-f]{2}){2}|(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})`)
)

func root(args []string) error {
	conf := &arpspoof.ARPSpoofConfig{}
	flags := flag.NewFlagSet(app, flag.ExitOnError)
	flags.StringVar(
		&conf.Targets,
		"t",
		"",
		"Targets for ARP spoofing. Example: \"targets 10.0.0.1,10.0.0.5-10,192.168.1.*,192.168.10.0/24\" (Default: entire subnet)",
	)
	gw := flags.String("g", "", "IPv4 address of custom gateway (Default: default gateway)")
	flags.StringVar(&conf.Interface, "i", "", "The name of the network interface. Example: eth0 (Default: default interface)")
	flags.BoolVar(&conf.FullDuplex, "f", false, "Run ARP spoofing in fullduplex mode")
	flags.BoolVar(&conf.Debug, "d", false, "Enable debug logging")
	nocolor := flags.Bool("nocolor", false, "Disable colored output")
	flags.BoolFunc("I", "Display list of interfaces and exit.", func(flagValue string) error {
		if err := network.DisplayInterfaces(false); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", app, err)
			os.Exit(2)
		}
		os.Exit(0)
		return nil
	})
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *gw != "" {
		ip, err := netip.ParseAddr(*gw)
		if err != nil {
			return err
		}
		conf.Gateway = &ip
	}
	output := zerolog.ConsoleWriter{Out: os.Stdout, NoColor: *nocolor}
	output.FormatTimestamp = func(i any) string {
		ts, _ := time.Parse(time.RFC3339, i.(string))
		if *nocolor {
			return colors.WrapBrackets(ts.Format(time.TimeOnly))
		}
		return colors.Gray(colors.WrapBrackets(ts.Format(time.TimeOnly))).String()
	}
	output.FormatMessage = func(i any) string {
		if i == nil || i == "" {
			return ""
		}
		s := i.(string)
		if *nocolor {
			return s
		}
		result := ipPortPattern.ReplaceAllStringFunc(s, func(match string) string {
			return colors.Gray(match).String()
		})
		result = macPattern.ReplaceAllStringFunc(result, func(match string) string {
			return colors.Yellow(match).String()
		})
		return result
	}
	logger := zerolog.New(output).With().Timestamp().Logger()
	conf.Logger = &logger
	arpspoofer, err := arpspoof.NewARPSpoofer(conf)
	if err != nil {
		return err
	}
	go arpspoofer.Start()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	return arpspoofer.Stop()
}

func main() {
	if err := root(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", app, err)
		os.Exit(2)
	}
}
