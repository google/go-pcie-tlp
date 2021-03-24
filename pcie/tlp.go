// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pcie builds and parses PCIe Transport Layer Packets (TLP).
package pcie

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
)

// abbreviations
var (
	be = binary.BigEndian
)

// errors
var (
	ErrBadType    = errors.New("bad TLP header type")
	ErrBadLength  = errors.New("bad TLP data length")
	ErrBadAddress = errors.New("bad TLP address")
	ErrTooShort   = errors.New("TLP packet too short")
)

const (
	dwordLen   = 4
	maxDataLen = 1024 * dwordLen
	// MaxTLPBuffer is a 4 dword header + max data payload.
	MaxTLPBuffer = 4*dwordLen + maxDataLen*dwordLen
)

const (
	fmt3DWNoData   = 0b000
	fmt4DWNoData   = 0b001
	fmt3DWWithData = 0b010
	fmt4DWWithData = 0b011
	fmtTlpPrefix   = 0b100
)

// TlpType is the format and type field in the TLP header.
// See Table 2-3 in PCI EXPRESS BASE SPECIFICATION, REV. 3.1a.
type TlpType uint8

const (
	// MRd3 is a Memory Read Request encoded with 3 dwords.
	MRd3 TlpType = (fmt3DWNoData << 5) | 0b00000
	// MRd4 is a Memory Read Request encoded with 4 dwords.
	MRd4 TlpType = (fmt4DWNoData << 5) | 0b00000
	// MRdLk3 is a Memory Read Request-Locked encoded with 3 dwords.
	MRdLk3 TlpType = (fmt3DWNoData << 5) | 0b00001
	// MRdLk4 is a Memory Read Request-Locked encoded with 4 dwords.
	MRdLk4 TlpType = (fmt4DWNoData << 5) | 0b00001
	// MWr3 is a Memory Write Request encoded with 3 dwords.
	MWr3 TlpType = (fmt3DWWithData << 5) | 0b00000
	// MWr4 is a Memory Write Request encoded with 4 dwords.
	MWr4 TlpType = (fmt4DWWithData << 5) | 0b00000
	// IORdT is an I/O Read Request.
	IORdT TlpType = (fmt3DWNoData << 5) | 0b00010
	// IOWrtT is an I/O Write Request.
	IOWrtT TlpType = (fmt3DWWithData << 5) | 0b00010
	// CfgRd0 is a Configuration Read of Type 0.
	CfgRd0 TlpType = (fmt3DWNoData << 5) | 0b00100
	// CfgWr0 is a Configuration Write of Type 0.
	CfgWr0 TlpType = (fmt3DWWithData << 5) | 0b00100
	// CfgRd1 is a Configuration Read of Type 1.
	CfgRd1 TlpType = (fmt3DWNoData << 5) | 0b00101
	// CfgWr1 is a Configuration Write of Type 1.
	CfgWr1 TlpType = (fmt3DWWithData << 5) | 0b00101
	// CplE is a Completion without Data. Used for I/O and
	// Configuration Write Completions with any
	// Completion Status.
	CplE TlpType = (fmt3DWNoData << 5) | 0b01010
	// CplD is a Completion with Data. Used for Memory,
	// I/O, and Configuration Read Completions.
	CplD TlpType = (fmt3DWWithData << 5) | 0b01010
	// CplLk is a Completion for Locked Memory Read without
	// Data. Used only in error case.
	CplLk TlpType = (fmt3DWNoData << 5) | 0b01011
	// CplLkD is a Completion for Locked Memory Read –
	// otherwise like CplD.
	CplLkD TlpType = (fmt3DWWithData << 5) | 0b01011
	// MRIOV is a Multi-Root I/O Virtualization and Sharing (MR-IOV) TLP prefix.
	MRIOV TlpType = (fmtTlpPrefix << 5) | 0b00000
	// LocalVendPrefix is a Local TLP prefix with vendor sub-field.
	LocalVendPrefix TlpType = (fmtTlpPrefix << 5) | 0b01110
	// ExtTPH is an Extended TPH TLP prefix.
	ExtTPH TlpType = (fmtTlpPrefix << 5) | 0b10000
	// PASID is a Process Address Space ID (PASID) TLP Prefix.
	PASID TlpType = (fmtTlpPrefix << 5) | 0b10001
	// EndEndVendPrefix is an End-to-End TLP prefix with vendor sub-field.
	EndEndVendPrefix TlpType = (fmtTlpPrefix << 5) | 0b11110
)

// AddressType is the address type field in the request header.
type AddressType uint8

// Supported address types.
const (
	DefaultUntranslated AddressType = 0b00
	TranslationRequest  AddressType = 0b01
	Translated          AddressType = 0b10
	AddressTypeReserved AddressType = 0b11
)

// TrafficClass is the traffic class field in the request header and used
// to set quality of service (QoS).
type TrafficClass uint8

// Supported traffic classes.
const (
	TC0 TrafficClass = iota
	TC1
	TC2
	TC3
	TC4
	TC5
	TC6
	TC7
)

// CompletionStatus is the completion status field in the completion header.
type CompletionStatus uint8

// Supported completion status.
const (
	SuccessfulCompletion      CompletionStatus = 0b000
	UnsupportedRequest        CompletionStatus = 0b001
	ConfigurationRequestRetry CompletionStatus = 0b010
	CompleterAbort            CompletionStatus = 0b100
)

// Address is the address field in the request header.
type Address uint64

func (a Address) is64() bool {
	return a > math.MaxUint32
}

func (a Address) toBuffer(buf *bytes.Buffer) {
	if a.is64() {
		binary.Write(buf, binary.BigEndian, uint32(a>>32))
	}
	// The 2 lower bits of the Address are reserved for TLP processing hint.
	// See Figure 2-8: "32-bit Address Routing" and
	//     Figure 2-7: "64-bit Address Routing".
	binary.Write(buf, binary.BigEndian, uint32(a&0xfffffffc))
}

func (a *Address) fromBuffer(is64 bool, buf *bytes.Buffer) {
	if is64 {
		var high uint32
		binary.Read(buf, binary.BigEndian, &high)
		*a = Address(uint64(high) << 32)
	}
	var low uint32
	binary.Read(buf, binary.BigEndian, &low)
	*a |= Address(low)
}

// TlpHeader is the first header dword, common on all TLPs.
// See section 2.2.1. Common Packet Header Fields.
type TlpHeader struct {
	// Format and type.
	Type TlpType
	// Traffic class (3b).
	TC TrafficClass
	// Indicates that a Memory Request is an LN Read or LN Write (1b).
	LN bool
	// Presence of TLP Processing Hints (1b).
	TH bool
	// Presence of TLP digest in the form of a single DW at the end of the TLP (1b).
	TD bool
	// Indicates the TLP is poisoned (1b).
	EP bool
	// Attributes (3b): no-snoop, relaxed ordering, id-based ordering.
	NS  bool
	RO  bool
	IBO bool
	// Address Type (2b).
	AT AddressType
	// Length of data payload in DW (10b).
	Length int
}

func computeBit(value bool, pos int) int {
	if value {
		return 1 << pos
	}
	return 0
}

func (h *TlpHeader) toBuffer(buf *bytes.Buffer) {
	dw := make([]byte, dwordLen)
	dw[0] = byte(h.Type)
	dw[1] = byte(
		(int(h.TC) << 4) |
			computeBit(h.IBO, 2) |
			computeBit(h.LN, 1) |
			computeBit(h.TH, 0))
	dw[2] = byte(
		computeBit(h.TD, 7) |
			computeBit(h.EP, 6) |
			computeBit(h.RO, 5) |
			computeBit(h.NS, 4) |
			(int(h.AT) << 2) |
			((h.Length >> 8) & 3))
	dw[3] = byte(h.Length & 0xff)
	buf.Write(dw)
}

func getSubField(input byte, shift, mask int) int {
	return (int(input) >> shift) & mask
}

func getBit(input byte, pos int) bool {
	return int(input>>pos)&1 > 0
}

func (h *TlpHeader) fromBuffer(buf *bytes.Buffer) {
	dw := buf.Next(dwordLen)
	h.Type = TlpType(uint8(dw[0]))
	h.TC = TrafficClass(getSubField(dw[1], 4, 7))
	h.IBO = getBit(dw[1], 2)
	h.LN = getBit(dw[1], 1)
	h.TH = getBit(dw[1], 0)
	h.TD = getBit(dw[2], 7)
	h.EP = getBit(dw[2], 6)
	h.RO = getBit(dw[2], 5)
	h.NS = getBit(dw[2], 4)
	h.AT = AddressType(getSubField(dw[2], 2, 3))
	h.Length = getSubField(dw[2], 0, 3)<<8 | int(dw[3])
}

// setLength sets the encoded TLP data length based on Table 2-4
// Length[9:0] Field Encoding.
func (h *TlpHeader) setLength(bytesLen int) error {
	if bytesLen&3 > 0 {
		return fmt.Errorf("%w: TLP length %d is not dword aligned", ErrBadLength, bytesLen)
	}
	if bytesLen > maxDataLen {
		return fmt.Errorf("%w: TLP length %d is too big, expected <= %d", ErrBadLength, bytesLen, maxDataLen)
	}

	h.Length = bytesLen >> 2
	if h.Length == 1024 {
		h.Length = 0
	}
	return nil
}

// DataLength decodes h.Length to data length.
// See Table 2-4 Length[9:0] Field Encoding.
func (h *TlpHeader) DataLength() int {
	l := h.Length
	if l == 0 {
		l = 1024
	}
	return l * dwordLen
}

// DeviceID is a configuration space address that uniquely identifies
// the device on the PCIe fabric.
type DeviceID struct {
	Bus      uint8
	Device   uint8
	Function uint8
}

func (id *DeviceID) toBytes() []byte {
	b := make([]byte, 2)
	be.PutUint16(b, id.ToUint16())
	return b
}

func (id *DeviceID) fromBytes(b []byte) {
	id.FromUint16(be.Uint16(b))
}

// ToUint16 encodes DeviceID to a uint16 value.
func (id *DeviceID) ToUint16() uint16 {
	return uint16(int(id.Bus)<<8 | int(id.Device)<<3 | int(id.Function))
}

// FromUint16 assigns DeviceID from an encoded uint16 value.
func (id *DeviceID) FromUint16(value uint16) {
	id.Bus = uint8(value >> 8)
	id.Device = uint8((value >> 3) & 0x1f)
	id.Function = uint8(value & 0x07)
}

// NewDeviceID builds a new DeviceID from an encoded uint16 value.
func NewDeviceID(value uint16) (addr DeviceID) {
	addr.FromUint16(value)
	return addr
}

func (id DeviceID) String() string {
	return fmt.Sprintf("%02x:%02x.%01x", id.Bus, id.Device, id.Function)
}

// FromString assigns DeviceID from an encoded string value.
func (id *DeviceID) FromString(value string) error {
	n, err := fmt.Sscanf(value, "%02x:%02x.%01x", &id.Bus, &id.Device, &id.Function)
	if n != 3 || err != nil {
		return err
	}
	return nil
}

// RequestHeader extends TlpHeader and includes the second header dword
// on Memory, IO, and Config Request TLPs.
type RequestHeader struct {
	TlpHeader
	// Requester ID.
	ReqID DeviceID
	// Unique tag for all outstanding requests.
	Tag uint8
	// First Byte Enable (4b).
	FirstBE uint8
	// Last Byte Enable (4b).
	LastBE uint8
}

func (h *RequestHeader) toBuffer(buf *bytes.Buffer) {
	h.TlpHeader.toBuffer(buf)

	dw := make([]byte, dwordLen)
	copy(dw[0:2], h.ReqID.toBytes())
	dw[2] = byte(h.Tag)
	dw[3] = byte(h.LastBE<<4 | h.FirstBE)
	buf.Write(dw)
}

func (h *RequestHeader) fromBuffer(buf *bytes.Buffer) {
	h.TlpHeader.fromBuffer(buf)

	dw := buf.Next(dwordLen)
	h.ReqID.fromBytes(dw[0:2])
	h.Tag = dw[2]
	h.FirstBE = uint8(getSubField(dw[3], 0, 0xf))
	h.LastBE = uint8(getSubField(dw[3], 4, 0xf))
}

func (h *RequestHeader) setByteEnables() {
	// See section 2.2.5. First/Last DW Byte Enables Rules.
	h.FirstBE = 0xf
	if h.Length == 1 {
		h.LastBE = 0
	} else {
		h.LastBE = 0xf
	}
}

// CplHeader extends TlpHeader and includes the second and third header dwords
// for Completion TLPs.
// See section 2.2.9. Completion Rules
type CplHeader struct {
	TlpHeader
	// Completer ID.
	CplID DeviceID
	// Byte count: the number of bytes left for transmission, including those in
	// the current packet (12b).
	BC int
	// Completion status.
	Status CompletionStatus
	// Requester ID.
	ReqID DeviceID
	// Unique tag for all outstanding requests.
	Tag uint8
	// Lower Byte Address for starting byte of Completion (7b).
	AddressLow uint8
}

func (h *CplHeader) toBuffer(buf *bytes.Buffer) {
	h.TlpHeader.toBuffer(buf)

	dw1 := make([]byte, dwordLen)
	copy(dw1[0:2], h.CplID.toBytes())
	dw1[2] = byte(
		(int(h.Status) << 5) |
			(h.BC>>8)&0xf)
	dw1[3] = byte(h.BC & 0xff)
	buf.Write(dw1)

	dw2 := make([]byte, dwordLen)
	copy(dw2[0:2], h.ReqID.toBytes())
	dw2[2] = byte(h.Tag)
	dw2[3] = byte(h.AddressLow & 0x7f)
	buf.Write(dw2)
}

func (h *CplHeader) fromBuffer(buf *bytes.Buffer) {
	h.TlpHeader.fromBuffer(buf)

	dw1 := buf.Next(dwordLen)
	h.CplID.fromBytes(dw1[0:2])
	h.Status = CompletionStatus(getSubField(dw1[2], 5, 7))
	h.BC = getSubField(dw1[2], 0, 0xf)<<8 | int(dw1[3])

	dw2 := buf.Next(dwordLen)
	h.ReqID.fromBytes(dw2[0:2])
	h.Tag = uint8(dw2[2])
	h.AddressLow = uint8(dw2[3] & 0x7f)
}

// MRd TLP: Memory read request.
type MRd struct {
	RequestHeader
	Address Address
}

// ToBytes encodes MRd to wire format.
func (tlp *MRd) ToBytes() []byte {
	buf := new(bytes.Buffer)
	tlp.RequestHeader.toBuffer(buf)
	tlp.Address.toBuffer(buf)
	return buf.Bytes()
}

// NewMRd builds memory read request.
// |length| is the number of BYTES to read and must be DWORD aligned.
func NewMRd(reqID DeviceID, tag uint8, addr uint64, length uint32) (*MRd, error) {
	tlp := &MRd{}
	tlp.Address = Address(addr)
	if tlp.Address.is64() {
		tlp.Type = MRd4
	} else {
		tlp.Type = MRd3
	}

	if err := tlp.setLength(int(length)); err != nil {
		return nil, err
	}

	tlp.ReqID = reqID
	tlp.Tag = tag
	tlp.setByteEnables()
	return tlp, nil
}

// NewMRdFromBytes builds a memory read request from a TLP buffer.
func NewMRdFromBytes(b []byte) (*MRd, error) {
	if len(b) < 3*dwordLen {
		return nil, fmt.Errorf("%w: TLP buffer too short (%d), expected at least 12 bytes", ErrTooShort, len(b))
	}
	// Verify type.
	var hdr TlpHeader
	hdr.fromBuffer(bytes.NewBuffer(b))
	if hdr.Type != MRd3 && hdr.Type != MRd4 {
		return nil, fmt.Errorf("%w: type %x is not supported. supported types: MRd3, MRd4", ErrBadType, hdr.Type)
	}
	if hdr.Type == MRd3 && len(b) < 3*dwordLen {
		return nil, fmt.Errorf("%w: TLP buffer too short (%d), want at least %d", ErrTooShort, len(b), 3*dwordLen)
	}
	if hdr.Type == MRd4 && len(b) < 4*dwordLen {
		return nil, fmt.Errorf("%w: TLP buffer too short (%d), want at least %d", ErrTooShort, len(b), 4*dwordLen)
	}
	// Decode MRd.
	tlp := &MRd{}
	buf := bytes.NewBuffer(b)
	tlp.RequestHeader.fromBuffer(buf)
	is64 := hdr.Type == MRd4
	tlp.Address.fromBuffer(is64, buf)
	return tlp, nil
}

// MWr TLP: Memory write request.
type MWr struct {
	RequestHeader
	Address Address
	Data    []byte
}

// ToBytes encodes MWr to wire format.
func (tlp *MWr) ToBytes() []byte {
	buf := new(bytes.Buffer)
	tlp.RequestHeader.toBuffer(buf)
	tlp.Address.toBuffer(buf)
	buf.Write(tlp.Data)
	return buf.Bytes()
}

// NewMWr builds memory write request.
// len(data) must be DWORD aligned.
func NewMWr(reqID DeviceID, addr uint64, data []byte) (*MWr, error) {
	tlp := &MWr{}
	tlp.Address = Address(addr)
	if tlp.Address.is64() {
		tlp.Type = MWr4
	} else {
		tlp.Type = MWr3
	}

	if err := tlp.setLength(len(data)); err != nil {
		return nil, err
	}

	tlp.ReqID = reqID
	tlp.Tag = 0
	tlp.setByteEnables()

	tlp.Data = make([]byte, len(data))
	copy(tlp.Data, data)
	return tlp, nil
}

// NewMWrFromBytes builds a memory write request from a TLP buffer.
func NewMWrFromBytes(b []byte) (*MWr, error) {
	if len(b) < 3*dwordLen {
		return nil, fmt.Errorf("%w: TLP buffer too short (%d), expected at least 12 bytes", ErrTooShort, len(b))
	}
	// Verify type.
	var hdr TlpHeader
	hdr.fromBuffer(bytes.NewBuffer(b))
	if hdr.Type != MWr3 && hdr.Type != MWr4 {
		return nil, fmt.Errorf("%w: type %x is not supported. supported types: MWr3, MWr4", ErrBadType, hdr.Type)
	}
	if hdr.Type == MWr3 && len(b) < 3*dwordLen {
		return nil, fmt.Errorf("%w: TLP buffer too short (%d), want at least %d", ErrTooShort, len(b), 3*dwordLen)
	}
	if hdr.Type == MWr4 && len(b) < 4*dwordLen {
		return nil, fmt.Errorf("%w: TLP buffer too short (%d), want at least %d", ErrTooShort, len(b), 4*dwordLen)
	}
	// Decode MWr.
	tlp := &MWr{}
	buf := bytes.NewBuffer(b)
	tlp.RequestHeader.fromBuffer(buf)
	is64 := hdr.Type == MWr4
	tlp.Address.fromBuffer(is64, buf)

	tlp.Data = make([]byte, tlp.DataLength())
	if buf.Len() < len(tlp.Data) {
		return nil, fmt.Errorf("%w: TLP data too short (%d), expected %d bytes", ErrTooShort, buf.Len(), len(tlp.Data))
	}
	copy(tlp.Data, buf.Next(len(tlp.Data)))
	return tlp, nil
}

// Cpl TLP: Completion response.
type Cpl struct {
	CplHeader
	Data []byte
}

// ToBytes encodes Cpl to wire format.
func (tlp *Cpl) ToBytes() []byte {
	buf := new(bytes.Buffer)
	tlp.CplHeader.toBuffer(buf)
	buf.Write(tlp.Data)
	return buf.Bytes()
}

// NewCplFromBytes builds completion response from TLP buffer.
func NewCplFromBytes(b []byte) (*Cpl, error) {
	if len(b) < 3*dwordLen {
		return nil, fmt.Errorf("%w: TLP buffer too short (%d), expected at least 12 bytes", ErrTooShort, len(b))
	}

	// Verify type.
	var hdr TlpHeader
	hdr.fromBuffer(bytes.NewBuffer(b))
	if hdr.Type != CplE && hdr.Type != CplD {
		return nil, fmt.Errorf("%w: type %x is not supported. Supported types: CplE, CplD", ErrBadType, hdr.Type)
	}

	// Decode CPL.
	tlp := &Cpl{}
	buf := bytes.NewBuffer(b)
	tlp.CplHeader.fromBuffer(buf)
	if tlp.Type == CplD {
		tlp.Data = make([]byte, tlp.DataLength())
		if buf.Len() < len(tlp.Data) {
			return nil, fmt.Errorf("%w: TLP data too short (%d), expected %d bytes", ErrTooShort, buf.Len(), len(tlp.Data))
		}
		copy(tlp.Data, buf.Next(len(tlp.Data)))
	}
	return tlp, nil
}

// NewCpl builds completion response.
func NewCpl(cplID DeviceID, bc int, status CompletionStatus, reqID DeviceID, tag, addressLow uint8, data []byte) (*Cpl, error) {
	tlp := &Cpl{}
	tlp.CplID = cplID
	tlp.BC = bc
	tlp.Status = status
	tlp.ReqID = reqID
	tlp.Tag = tag
	tlp.AddressLow = addressLow

	if len(data) > 0 {
		tlp.Type = CplD
		if err := tlp.setLength(len(data)); err != nil {
			return nil, err
		}
		tlp.Data = make([]byte, len(data))
		copy(tlp.Data, data)
	} else {
		tlp.Type = CplE
	}
	return tlp, nil
}

// See Table 2-37: Calculating Byte Count from Length and Byte Enables.
func CplCalcByteCount(firstBE, lastBE, length int) int {
	if firstBE&0b1001 == 0b1001 && lastBE == 0b0000 {
		return 4
	}
	if firstBE&0b1101 == 0b0101 && lastBE == 0b0000 {
		return 3
	}
	if firstBE&0b1011 == 0b1010 && lastBE == 0b0000 {
		return 3
	}
	if firstBE == 0b0011 && lastBE == 0b0000 {
		return 2
	}
	if firstBE == 0b0110 && lastBE == 0b0000 {
		return 2
	}
	if firstBE == 0b1100 && lastBE == 0b0000 {
		return 2
	}
	if firstBE == 0b0001 && lastBE == 0b0000 {
		return 1
	}
	if firstBE == 0b0010 && lastBE == 0b0000 {
		return 1
	}
	if firstBE == 0b0100 && lastBE == 0b0000 {
		return 1
	}
	if firstBE == 0b1000 && lastBE == 0b0000 {
		return 1
	}
	if firstBE == 0b0000 && lastBE == 0b0000 {
		return 1
	}
	if firstBE&0b0001 == 0b0001 && lastBE&0b1000 == 0b1000 {
		return length * 4
	}
	if firstBE&0b0001 == 0b0001 && lastBE&0b1100 == 0b0100 {
		return length*4 - 1
	}
	if firstBE&0b0001 == 0b0001 && lastBE&0b1110 == 0b0010 {
		return length*4 - 2
	}
	if firstBE&0b0001 == 0b0001 && lastBE == 0b0001 {
		return length*4 - 3
	}
	if firstBE&0b0011 == 0b0010 && lastBE&0b1000 == 0b1000 {
		return length*4 - 1
	}
	if firstBE&0b0011 == 0b0010 && lastBE&0b1100 == 0b0100 {
		return length*4 - 2
	}
	if firstBE&0b0011 == 0b0010 && lastBE&0b1110 == 0b0010 {
		return length*4 - 3
	}
	if firstBE&0b0011 == 0b0010 && lastBE == 0b0001 {
		return length*4 - 4
	}
	if firstBE&0b0111 == 0b0100 && lastBE&0b1000 == 0b1000 {
		return length*4 - 2
	}
	if firstBE&0b0111 == 0b0100 && lastBE&0b1100 == 0b0100 {
		return length*4 - 3
	}
	if firstBE&0b0111 == 0b0100 && lastBE&0b1110 == 0b0010 {
		return length*4 - 4
	}
	if firstBE&0b0111 == 0b0100 && lastBE == 0b0001 {
		return length*4 - 5
	}
	if firstBE == 0b1000 && lastBE&0b1000 == 0b1000 {
		return length*4 - 3
	}
	if firstBE == 0b1000 && lastBE&0b1100 == 0b0100 {
		return length*4 - 4
	}
	if firstBE == 0b1000 && lastBE&0b1110 == 0b0010 {
		return length*4 - 5
	}
	if firstBE == 0b1000 && lastBE == 0b0001 {
		return length*4 - 6
	}
	return 0
}

// Table 2-38: Calculating Lower Address from 1st DW BE.
func CplCalcLowerAddress(firstBE int, readAddress Address) byte {
	addr := byte(readAddress & 0x7c)
	if firstBE == 0b0000 {
		return addr + 0b00
	}
	if firstBE&0b0001 == 0b0001 {
		return addr + 0b00
	}
	if firstBE&0b0011 == 0b0010 {
		return addr + 0b01
	}
	if firstBE&0b0111 == 0b0100 {
		return addr + 0b10
	}
	if firstBE == 0b1000 {
		return addr + 0b11
	}
	return 0
}

// NewCplForMrd builds a completion response that matches the given memory read request.
func NewCplForMrd(cplID DeviceID, status CompletionStatus, mrd *MRd, data []byte) (*Cpl, error) {
	if len(data) != mrd.DataLength() {
		return nil, fmt.Errorf("%w: buffer size (%d) does not match expected DataLength (%d)", ErrBadLength, len(data), mrd.DataLength())
	}
	bc := CplCalcByteCount(int(mrd.FirstBE), int(mrd.LastBE), mrd.Length)
	addressLow := CplCalcLowerAddress(int(mrd.FirstBE), mrd.Address)
	return NewCpl(cplID, bc, status, mrd.ReqID, mrd.Tag, addressLow, data)
}

// CfgHeader extends RequestHeader and includes the third header dword
// for configuration read TLPs.
type CfgHeader struct {
	RequestHeader
	Target DeviceID
	// Register number (6b)
	RegisterNumber int
	// Extended register number (4b)
	ExtRegisterNumber int
}

func (h *CfgHeader) toBuffer(buf *bytes.Buffer) {
	h.RequestHeader.toBuffer(buf)

	dw := make([]byte, dwordLen)
	copy(dw[0:2], h.Target.toBytes())
	dw[2] = byte(h.ExtRegisterNumber & 0xf)
	dw[3] = byte(h.RegisterNumber << 2)
	buf.Write(dw)
}
func (h *CfgHeader) fromBuffer(buf *bytes.Buffer) {
	h.RequestHeader.fromBuffer(buf)
	dw := buf.Next(dwordLen)
	h.Target.fromBytes(dw[0:2])
	h.ExtRegisterNumber = int(dw[2] & 0xf)
	h.RegisterNumber = int(dw[3]>>2) & 0x3f
}

// CfgRd TLP: Configuration read request.
type CfgRd struct {
	CfgHeader
}

// ToBytes encodes CfgRd to wire format.
func (tlp *CfgRd) ToBytes() []byte {
	buf := new(bytes.Buffer)
	tlp.CfgHeader.toBuffer(buf)
	return buf.Bytes()
}

// NewCfgRd builds configuration read request.
func NewCfgRd(reqID DeviceID, tag uint8, target DeviceID, register int) *CfgRd {
	tlp := &CfgRd{}
	// See Figure 2-18: Request Header Format for Configuration Transactions.
	tlp.Type = CfgRd0
	tlp.Length = 1
	tlp.ReqID = reqID
	tlp.Tag = tag
	tlp.FirstBE = 0xf
	tlp.LastBE = 0
	tlp.Target = target
	tlp.RegisterNumber = (register << 2) & 0x3f
	tlp.ExtRegisterNumber = register & 0xf
	return tlp
}

// CfgWr TLP: Configuration write request.
type CfgWr struct {
	CfgHeader
	Data []byte
}

// ToBytes encodes CfgWr to wire format.
func (tlp *CfgWr) ToBytes() []byte {
	buf := new(bytes.Buffer)
	tlp.CfgHeader.toBuffer(buf)
	buf.Write(tlp.Data)
	return buf.Bytes()
}

// NewCfgWr builds configuration write request.
func NewCfgWr(reqID DeviceID, tag uint8, target DeviceID, register int, data [4]byte) *CfgWr {
	tlp := &CfgWr{}
	// See Figure 2-18: Request Header Format for Configuration Transactions.
	tlp.Type = CfgWr0
	tlp.Length = 1
	tlp.ReqID = reqID
	tlp.Tag = tag
	tlp.FirstBE = 0xf
	tlp.LastBE = 0
	tlp.Target = target
	tlp.RegisterNumber = (register << 2) & 0x3f
	tlp.ExtRegisterNumber = register & 0xf
	tlp.Data = make([]byte, len(data))
	copy(tlp.Data, data[:])
	return tlp
}

// NewCfgWrFromBytes builds a memory read request from a TLP buffer.
func NewCfgWrFromBytes(b []byte) (*CfgWr, error) {
	if len(b) < 3*dwordLen {
		return nil, fmt.Errorf("%w: TLP buffer too short (%d), expected at least 12 bytes", ErrTooShort, len(b))
	}
	// Verify type.
	var hdr TlpHeader
	hdr.fromBuffer(bytes.NewBuffer(b))
	if hdr.Type != CfgWr0 && hdr.Type != CfgWr1 {
		return nil, fmt.Errorf("%w: type %x is not supported. supported types: CfgWr0, CfgWr1", ErrBadType, hdr.Type)
	}
	// Decode CfgWr.
	tlp := &CfgWr{}
	buf := bytes.NewBuffer(b)
	tlp.CfgHeader.fromBuffer(buf)
	tlp.Data = make([]byte, tlp.DataLength())
	if buf.Len() < len(tlp.Data) {
		return nil, fmt.Errorf("%w: TLP data too short (%d), expected %d bytes", ErrTooShort, buf.Len(), len(tlp.Data))
	}
	copy(tlp.Data, buf.Next(len(tlp.Data)))
	if tlp.Length != 1 {
		return nil, fmt.Errorf("%w: TLP bad length in request (%d), expected 1", ErrBadLength, tlp.Length)
	}
	if tlp.LastBE != 0 {
		return nil, fmt.Errorf("%w: TLP bad LastBE in request (%d), expected 0", ErrBadLength, tlp.LastBE)
	}
	return tlp, nil
}

// Returns the config space memory address.
// Table 7-1: Enhanced Configuration Address Mapping.
func (tlp *CfgWr) MemoryAddress() int {
	offset := bits.TrailingZeros8(tlp.FirstBE)
	return tlp.ExtRegisterNumber<<8 + tlp.RegisterNumber<<2 + offset
}

// Returns the first enabled data.
func (tlp *CfgWr) FirstDataByte() byte {
	offset := bits.TrailingZeros8(tlp.FirstBE)
	return tlp.Data[offset]
}

// IORd TLP: I/O read request.
type IORd struct {
	RequestHeader
	Address Address
}

// ToBytes encodes IORd to wire format.
func (tlp *IORd) ToBytes() []byte {
	buf := new(bytes.Buffer)
	tlp.RequestHeader.toBuffer(buf)
	tlp.Address.toBuffer(buf)
	return buf.Bytes()
}

// NewIORd builds memory read request.
// |length| is the number of BYTES to read and must be DWORD aligned.
func NewIORd(reqID DeviceID, tag uint8, addr uint64, length uint32) (*IORd, error) {
	tlp := &IORd{}
	tlp.Address = Address(addr)
	if tlp.Address.is64() {
		return nil, fmt.Errorf("%w: 64bit address %x is not supported", ErrBadAddress, tlp.Address)
	}
	tlp.Type = IORdT

	if err := tlp.setLength(int(length)); err != nil {
		return nil, err
	}

	tlp.ReqID = reqID
	tlp.Tag = tag
	tlp.setByteEnables()

	return tlp, nil
}

// IOWrt TLP: Memory write request.
type IOWrt struct {
	RequestHeader
	Address Address
	Data    []byte
}

// ToBytes encodes IOWrt to wire format.
func (tlp *IOWrt) ToBytes() []byte {
	buf := new(bytes.Buffer)
	tlp.RequestHeader.toBuffer(buf)
	tlp.Address.toBuffer(buf)
	buf.Write(tlp.Data)
	return buf.Bytes()
}

// NewIOWrt builds memory write request.
// len(data) must be DW aligned.
func NewIOWrt(reqID DeviceID, addr uint64, data []byte) (*IOWrt, error) {
	tlp := &IOWrt{}
	tlp.Address = Address(addr)
	if tlp.Address.is64() {
		return nil, fmt.Errorf("%w: 64bit address %x is not supported", ErrBadAddress, tlp.Address)
	}
	tlp.Type = IOWrtT

	if err := tlp.setLength(len(data)); err != nil {
		return nil, err
	}

	tlp.ReqID = reqID
	tlp.Tag = 0
	tlp.setByteEnables()

	tlp.Data = make([]byte, len(data))
	copy(tlp.Data, data)
	return tlp, nil
}
