# GO-PCIe-TLP

## About

This Go library builds and parses PCIe Transport Layer Packets (TLP) as
specified in the
[PCI Express base specification](https://pcisig.com/specifications/pciexpress).
Coupled with [go-pcie-screamer](https://github.com/google/go-pcie-screamer),
this library can be used to run PCIe security tests.

## Usage

```go
import "github.com/google/go-pcie-tlp/pcie"

// Build memory read TLP.
reqID = pcie.DeviceID {
  Bus:      0x61,
  Device:   0,
  Function: 0,
}
tag := uint8(0x80)
addr := uint64(0x12000)
maxLen := uint32(4096)
tlp, err := pcie.NewMRd(reqID, tag, addr, maxLen)

// Build memory write TLP.
data := []byte{0x41, 0x41, 0x41, 0x41}
tlp, err := pcie.NewMWr(reqID, tag, addr, data)

// Parse completion TLP.
buf := []byte{
  0x4a, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x10, 0x61, 0x00, 0x80, 0x00, 0x41, 0x41, 0x41, 0x41,
  0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41}
tlp, err := NewCplFromBytes(buf)
```

## Disclaimer

This is not an official Google product (experimental or otherwise), it is just
code that happens to be owned by Google.
