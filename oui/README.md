# OUI - Hardware Vendor Prefix For MAC Address

## Usage

```go
package main

import (
	"fmt"
	"net"

	"github.com/shadowy-pycoder/mshark/oui"
)

func main() {
    addr := net.HardwareAddr{0x00, 0x00, 0x0c, 0x01, 0x02, 0x03}
	fmt.Println(oui.VendorWithMAC(addr)) // Cisco_01:02:03
}
```

## Update OUI Data

```shell
go install github.com/magefile/mage@latest
mage clean && mage build
```
