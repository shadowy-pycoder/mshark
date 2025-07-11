![mshark_new](https://github.com/user-attachments/assets/ee1b9526-dcae-4ff8-962d-315897e49ed0)

# mShark - Mini [Wireshark](https://www.wireshark.org/) written in Go

[![Go Reference](https://pkg.go.dev/badge/github.com/shadowy-pycoder/mshark.svg)](https://pkg.go.dev/github.com/shadowy-pycoder/mshark)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/shadowy-pycoder/mshark)
[![Go Report Card](https://goreportcard.com/badge/github.com/shadowy-pycoder/mshark)](https://goreportcard.com/report/github.com/shadowy-pycoder/mshark)
![GitHub Release](https://img.shields.io/github/v/release/shadowy-pycoder/mshark)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/shadowy-pycoder/mshark/total)

## Installation

Download release from [Releases](https://github.com/shadowy-pycoder/mshark/releases) Page.

Or install using `go install` (requires Go 1.23+ but may work with older versions):

```shell
CGO_ENABLED=0 go install -ldflags "-s -w" -trimpath github.com/shadowy-pycoder/mshark/cmd/mshark@latest
```

This will install the `mshark` binary to your `$GOPATH/bin` directory.

If you are getting a `Permission denied` error when running `mshark`, try running

```shell
sudo setcap cap_net_raw+ep ~/go/bin/mshark
```

## Usage

```shell
mshark -h

                ______   __                            __
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

Usage: mshark [OPTIONS]
Options:
  -h    Show this help message and exit.
  -D    Display list of interfaces and exit.
  -b int
        The maximum size of packet queue. (default 8192)
  -c int
        The maximum number of packets to capture.
  -e string
        BPF filter expression. Example: "ip proto tcp"
  -f value
        File extension(s) to write captured data. Supported formats: stdout, txt, pcap, pcapng
  -i string
        The name of the network interface. Example: eth0 (default "any")
  -p    Promiscuous mode. This setting is ignored for "any" interface. Defaults to false.
  -s int
        The maximum length of each packet snapshot. Defaults to 65535.
  -t duration
        The maximum duration of the packet capture process. Example: 5s
  -v	Display full packet info when capturing to stdout or txt.
```

### Example

```shell
mshark -p -f=txt -f=stdout -f=pcapng -i eth0 -e="port 53"
```

The above command will capture packets containing `port 53` (assumed to be DNS queries) from the `eth0` interface and write the captured data to `stdout`, `txt`, and file in `pcapng` format. Files are created in the current working directory.

Output:

```shell
- Interface: eth0
- Snapshot Length: 65535
- Promiscuous Mode: true
- Timeout: 0s
- Number of Packets: 0
- Packet Buffer Size: 8192
- BPF Filter: "port 53"
- Verbose: false
```

![Screenshot from 2024-09-17 09-37-50](https://github.com/user-attachments/assets/44c233ee-85a4-43f2-8f65-1ef239362bab)

With `-v` flag enabled, you will see more detailed information:

![Screenshot from 2024-09-17 09-56-20](https://github.com/user-attachments/assets/11539ea7-779e-4faf-8fce-2eea9ab653c7)
![Screenshot from 2024-09-17 09-56-47](https://github.com/user-attachments/assets/26b6353d-d312-40c5-9917-3f2f7bb8abdc)

## Supported layers

- [Ethernet](https://en.wikipedia.org/wiki/Ethernet_frame)
- [IPv4](https://en.wikipedia.org/wiki/IPv4)
- [IPv6](https://en.wikipedia.org/wiki/IPv6)
- [ARP](https://en.wikipedia.org/wiki/Address_Resolution_Protocol)
- [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)
- [ICMPv6](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6)
- [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
- [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
- [DNS](https://en.wikipedia.org/wiki/Domain_Name_System)
- [HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol)
- [SNMP](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol)
- [FTP](https://en.wikipedia.org/wiki/File_Transfer_Protocol)
- [SSH](https://en.wikipedia.org/wiki/Secure_Shell)
- [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security)

## Roadmap

- [x] Online packet capture to `stdout`, `txt`, `pcap` and `pcapng` files
- [ ] Offline packet capture from `pcap` and `pcapng` files
- [ ] Add proper parsing for `SNMP` messages
- [ ] Add packet generation and packet injection functionality
