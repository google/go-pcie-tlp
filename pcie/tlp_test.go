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

package pcie

import (
	"bytes"
	"errors"
	"testing"
	"testing/quick"

	"github.com/google/go-cmp/cmp"
)

var (
	rootID = DeviceID{
		Bus:      0,
		Device:   0,
		Function: 0,
	}
	reqID = DeviceID{
		Bus:      0x61,
		Device:   0,
		Function: 0,
	}
)

// Round-trip Header encoding/decoding.
func TestHeaderEncoding(t *testing.T) {
	f := func(src TlpHeader) bool {
		src.TC &= 0x7
		src.AT &= 0x3
		src.Length &= 0x3ff
		buf := new(bytes.Buffer)
		src.toBuffer(buf)
		var dst TlpHeader
		dst.fromBuffer(buf)
		return cmp.Equal(src, dst)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Round-trip DeviceID encoding/decoding.
func TestDeviceIDUint16Encoding(t *testing.T) {
	f := func(src DeviceID) bool {
		src.Device &= 0x1f
		src.Function &= 0x7
		var dst DeviceID
		dst.FromUint16(src.ToUint16())
		return cmp.Equal(src, dst)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Round-trip DeviceID encoding/decoding.
func TestDeviceIDBytesEncoding(t *testing.T) {
	f := func(src DeviceID) bool {
		src.Device &= 0x1f
		src.Function &= 0x7
		var dst DeviceID
		dst.fromBytes(src.toBytes())
		return cmp.Equal(src, dst)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Round-trip DeviceID encoding/decoding.
func TestDeviceIDStringEncoding(t *testing.T) {
	f := func(src DeviceID) bool {
		src.Device &= 0x1f
		src.Function &= 0x7
		var dst DeviceID
		dst.FromString(src.String())
		return cmp.Equal(src, dst)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Round-trip RequestHeader encoding/decoding.
func TestRequestHeaderEncoding(t *testing.T) {
	f := func(src RequestHeader) bool {
		src.TC &= 0x7
		src.AT &= 0x3
		src.Length &= 0x3ff
		src.ReqID.Device &= 0x1f
		src.ReqID.Function &= 0x7
		src.FirstBE &= 0xf
		src.LastBE &= 0xf
		buf := new(bytes.Buffer)
		src.toBuffer(buf)

		var dst RequestHeader
		dst.fromBuffer(buf)
		return cmp.Equal(src, dst)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Round-trip CplHeader encoding/decoding.
func TestCplHeaderEncoding(t *testing.T) {
	f := func(src CplHeader) bool {
		src.TC &= 0x7
		src.AT &= 0x3
		src.Length &= 0x3ff
		src.CplID.Device &= 0x1f
		src.CplID.Function &= 0x7
		src.ReqID.Device &= 0x1f
		src.ReqID.Function &= 0x7
		src.Status &= 0x7
		src.BC &= 0xfff
		src.AddressLow &= 0x7f
		buf := new(bytes.Buffer)
		src.toBuffer(buf)

		var dst CplHeader
		dst.fromBuffer(buf)
		return cmp.Equal(src, dst)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Round-trip MRd encoding/decoding.
func TestMRdEncoding(t *testing.T) {
	f := func(reqID DeviceID, tag uint8, addr uint64, length uint32) bool {
		reqID.Device &= 0x1f
		reqID.Function &= 0x7
		addr &= ^uint64(3)
		length &= 0x3fc
		src, err := NewMRd(reqID, tag, addr, length)
		if err != nil {
			return false
		}
		dst, err := NewMRdFromBytes(src.ToBytes())
		if err != nil {
			return false
		}
		return cmp.Equal(src, dst)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestMRdEncodingMatchesPciLeech(t *testing.T) {
	tag := uint8(0x80)
	addr32 := uint64(0x12000)
	maxLen := uint32(4096)
	tlp, err := NewMRd(reqID, tag, addr32, maxLen)
	if err != nil {
		t.Fatalf("NewMRd(%d, %d, %d, %d) = _, %v, want nil err", reqID, tag, addr32, maxLen, err)
	}

	// Copied from pcileech:
	// TX: MRd32:  Len: 000 ReqID: 6100 BE_FL: ff Tag: 80 Addr: 00012000
	// 0000    00 00 00 00 61 00 80 ff  00 01 20 00               ....a..... .
	want := []byte{0x00, 0x00, 0x00, 0x00, 0x61, 0x00, 0x80, 0xff, 0x00, 0x01, 0x20, 0x00}
	got := tlp.ToBytes()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("MRd encoding with max length didn't match:\n%s", diff)
	}
}

func TestNewMRdFailsOnUnalignedLength(t *testing.T) {
	tag := uint8(0x80)
	addr32 := uint64(0x12000)
	unalignedLength := uint32(3)
	_, err := NewMRd(reqID, tag, addr32, unalignedLength)
	if !errors.Is(err, ErrBadLength) {
		t.Errorf("NewMRd(%d, %d, %d, %d) = _, %v, want ErrBadLength", reqID, tag, addr32, unalignedLength, err)
	}
}

func TestNewMRdFailsOnBigLength(t *testing.T) {
	tag := uint8(0x80)
	addr32 := uint64(0x12000)
	bigLength := uint32(4100)
	_, err := NewMRd(reqID, tag, addr32, bigLength)
	if !errors.Is(err, ErrBadLength) {
		t.Errorf("NewMRd(%d, %d, %d, %d) = _, %v, want ErrBadLength", reqID, tag, addr32, bigLength, err)
	}
}

func TestMWrEncodingMatchesPciLeech(t *testing.T) {
	// Copied from pcileech:
	// 	TX: MWr32:  Len: 020 ReqID: 6100 BE_FL: ff Tag: 00 Addr: 0012cf80
	// 0000    40 00 00 20 61 00 00 ff  00 12 cf 80 41 41 41 41   @.. a.......AAAA
	// 0010    41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA
	// 0020    41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA
	// 0030    41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA
	// 0040    41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA
	// 0050    41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA
	// 0060    41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA
	// 0070    41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA
	// 0080    41 41 41 41 41 41 41 41  41 41 41 41               AAAAAAAAAAAA
	addr32 := uint64(0x12cf80)
	data := []byte{
		0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	}
	tlp, err := NewMWr(reqID, addr32, data)
	if err != nil {
		t.Fatalf("NewMWr(%d, %d, %X) = _, %v, want nil err", reqID, addr32, data, err)
	}

	want := []byte{
		0x40, 0x00, 0x00, 0x20, 0x61, 0x00, 0x00, 0xff, 0x00, 0x12, 0xcf, 0x80, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	}
	got := tlp.ToBytes()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("MWr encoding didn't match recorded:\n%s", diff)
	}
}

// Round-trip MWr encoding/decoding.
func TestMWrEncoding(t *testing.T) {
	f := func(reqID DeviceID, addr uint64, data []byte) bool {
		reqID.Device &= 0x1f
		reqID.Function &= 0x7
		addr &= ^uint64(3)
		if len(data) < 4 {
			// Empty / short data buffer not supported.
			return true
		}
		src, err := NewMWr(reqID, addr, data[:len(data)&0x3fc])
		if err != nil {
			return false
		}
		dst, err := NewMWrFromBytes(src.ToBytes())
		if err != nil {
			return false
		}
		return cmp.Equal(src, dst)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Round-trip Cpl encoding/decoding.
func TestCplEncoding(t *testing.T) {
	f := func(cplID DeviceID, bc int, status CompletionStatus, reqID DeviceID, tag, addressLow uint8, data []byte) bool {
		cplID.Device &= 0x1f
		cplID.Function &= 0x7
		bc &= 0xfff
		status &= 0x7
		reqID.Device &= 0x1f
		reqID.Function &= 0x7
		addressLow &= 0x7f
		src, err := NewCpl(cplID, bc, status, reqID, tag, addressLow, data[:len(data)&0x3fc])
		if err != nil {
			return false
		}
		dst, err := NewCplFromBytes(src.ToBytes())
		if err != nil {
			return false
		}
		return cmp.Equal(src, dst)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestCplDecodingMatchesPciLeech(t *testing.T) {
	// Copied off the wire [TLP-RX]:
	// 00000000  4a 00 00 04 00 00 00 10  61 00 80 00 41 41 41 41  |J.......a...AAAA|
	// 00000010  41 41 41 41 41 41 41 41  41 41 41 41              |AAAAAAAAAAAA|
	buf := []byte{
		0x4a, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x10, 0x61, 0x00, 0x80, 0x00, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41}
	tlp, err := NewCplFromBytes(buf)
	if err != nil {
		t.Errorf("NewCplFromBytes(%X) = _, %v, want nil err", buf, err)
	}
	if diff := cmp.Diff(rootID, tlp.CplID); diff != "" {
		t.Errorf("Unexpected CplID:\n%s", diff)
	}
	if diff := cmp.Diff(reqID, tlp.ReqID); diff != "" {
		t.Errorf("Unexpected ReqID:\n%s", diff)
	}
	if tlp.BC != tlp.Length*4 {
		t.Errorf("Unexpected byte count (%v)", tlp.BC)
	}
	want := []byte{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41}
	if diff := cmp.Diff(want, tlp.Data); diff != "" {
		t.Errorf("Unexpected Data:\n%s", diff)
	}
}

func TestCplForMrd(t *testing.T) {
	tag := uint8(0x80)
	addr32 := uint64(0x12340)
	data := []byte{1, 2, 3, 4}
	mrd, err := NewMRd(reqID, tag, addr32, uint32(len(data)))
	if err != nil {
		t.Fatalf("NewMRd(%d, %d, %d, %d) = _, %v, want nil err", reqID, tag, addr32, len(data), err)
	}
	cpl, err := NewCplForMrd(rootID, SuccessfulCompletion, mrd, data)
	if err != nil {
		t.Fatalf("NewCplForMrd(%v, %d, %v, % X) = _, %v, want nil err", rootID, SuccessfulCompletion, mrd, data, err)
	}
	if cpl.AddressLow != byte(addr32&0x7f) {
		t.Errorf("Unexpected AddressLow (%d)", cpl.AddressLow)
	}
	if cpl.Tag != tag {
		t.Errorf("Unexpected tag (%d)", cpl.Tag)
	}
	if cpl.BC != len(data) {
		t.Errorf("Unexpected BC (%d)", cpl.BC)
	}
	if diff := cmp.Diff(data, cpl.Data); diff != "" {
		t.Errorf("Unexpected Data:\n%s", diff)
	}
}

func TestCplDecodingFailsOnSmallPacket(t *testing.T) {
	buf := []byte{
		0x4a, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x10, 0x61, 0x00, 0x80}
	_, err := NewCplFromBytes(buf)
	if !errors.Is(err, ErrTooShort) {
		t.Errorf("NewCplFromBytes(%X) = _, %v, want ErrTooShort", buf, err)
	}
}

func TestCplDecodingFailsOnUnsupportedType(t *testing.T) {
	buf := []byte{
		0xcc, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x10, 0x61, 0x00, 0x80, 0x00, 0x41, 0x41, 0x41, 0x41,
	}
	_, err := NewCplFromBytes(buf)
	if !errors.Is(err, ErrBadType) {
		t.Errorf("NewCplFromBytes(%X) = _, %v, want ErrBadType", buf, err)
	}
}

func TestCplDecodingFailsOnTruncatedPayload(t *testing.T) {
	buf := []byte{
		0x4a, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x10, 0x61, 0x00, 0x80, 0x00, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41}
	_, err := NewCplFromBytes(buf)
	if !errors.Is(err, ErrTooShort) {
		t.Errorf("NewCplFromBytes(%X) = _, %v, want ErrTooShort", buf, err)
	}
}

// Round-trip CfgWr encoding/decoding.
func TestCfgWrEncoding(t *testing.T) {
	f := func(reqID DeviceID, tag uint8, target DeviceID, register int, data [4]byte) bool {
		reqID.Device &= 0x1f
		reqID.Function &= 0x7
		target.Device &= 0x1f
		target.Function &= 0x7
		register &= 0x3ff
		src := NewCfgWr(reqID, tag, target, register, data)
		dst, err := NewCfgWrFromBytes(src.ToBytes())
		if err != nil {
			return false
		}
		return cmp.Equal(src, dst)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestIOTlpDoNotSupport64bitAddresses(t *testing.T) {
	addr64 := uint64(0xffffffff00012000)
	_, err := NewIORd(reqID, 0x80, addr64, 4)
	if !errors.Is(err, ErrBadAddress) {
		t.Errorf("NewIORd(%d, %d, %d, %d) = _, %v, want ErrBadAddress", reqID, 0x80, addr64, 4, err)
	}
	data := []byte{0x11, 0x22, 0x33, 0x44}
	_, err = NewIOWrt(reqID, addr64, data)
	if !errors.Is(err, ErrBadAddress) {
		t.Errorf("NewIOWrt(%d, %d, %X) = _, %v, want ErrBadAddress", reqID, addr64, data, err)
	}
}
