// not used package
package rtpdump

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"unsafe"
)

type TimeVal struct {
	Sec  uint32
	USec uint32
}

func (tv *TimeVal) Unmarshal(reader io.Reader) error {
	err := binary.Read(reader, binary.BigEndian, tv)
	return err
}

type RtpDumpHdr struct {
	Start   TimeVal
	Source  uint32
	Port    uint16
	Padding uint16
}

func (hdr *RtpDumpHdr) Unmarshal(reader io.Reader) error {
	err := binary.Read(reader, binary.BigEndian, hdr)
	return err
}

func (hdr *RtpDumpHdr) String() string {
	m := make(map[string]interface{})
	b, _ := json.Marshal(hdr.Start)
	m["Start"] = string(b)
	ip := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, hdr.Source)
	m["Source"] = ip.String()
	m["Port"] = hdr.Port
	b, _ = json.Marshal(m)
	return string(b)
}

type RtpPktHdr struct {
	Length uint16 // length include this header
	PLen   uint16
	Offset uint32
}

type RtpPkt struct {
	RtpPktHdr
	Payload []byte
}

func (pkt *RtpPkt) Unmarshal(reader io.Reader) error {
	err := binary.Read(reader, binary.BigEndian, &pkt.RtpPktHdr)
	if err != nil {
		return err
	}
	if uintptr(pkt.Length) < unsafe.Sizeof(pkt.RtpPktHdr) {
		return fmt.Errorf("small size of read %v < %v", pkt.Length, unsafe.Sizeof(pkt.RtpPktHdr))
	}
	length := uintptr(pkt.Length) - unsafe.Sizeof(pkt.RtpPktHdr)
	if length > 0 {
		pkt.Payload = make([]byte, length)
		var n int
		n, err = reader.Read(pkt.Payload)
		if err != nil {
			return err
		}
		if n < int(length) {
			return fmt.Errorf("small size of read %v < %v", n, length)
		}
	}
	return nil
}

func readHeader(reader io.Reader) (*RtpDumpHdr, error) {
	magic := fmt.Sprintf("#!rtpplay%s ", "1.0")
	buf := make([]byte, len(magic))
	n, err := reader.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < len(buf) {
		return nil, fmt.Errorf("small size of read header %v < %v", n, len(buf))
	}
	if bytes.Compare(buf, []byte(magic)) != 0 {
		return nil, fmt.Errorf("invalid header %s != %s", buf, magic)
	}
	fileHdr := &RtpDumpHdr{}
	err = fileHdr.Unmarshal(reader)
	if err != nil {
		return nil, err
	}
	return fileHdr, nil
}
