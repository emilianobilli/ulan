package ulan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/net/ipv4"
)

type EthernetType uint16

const (
	EthernetHdrSize = 14
	IPHdrSize       = 20
	MTU             = 1456
)
const (
	// EthernetTypeLLC is not an actual ethernet type.  It is instead a
	// placeholder we use in Ethernet frames that use the 802.3 standard of
	// srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
	EthernetTypeLLC  EthernetType = 0
	EthernetTypeIPv4 EthernetType = 0x0800
)

type Ethernet struct {
	SrcMAC       net.HardwareAddr
	DstMAC       net.HardwareAddr
	EthernetType EthernetType
	Length       uint16
}

func (eth *Ethernet) decodeFromBytes(data []byte) error {
	if len(data) < 14 {
		return errors.New("Ethernet packet too small")
	}
	eth.DstMAC = net.HardwareAddr(data[0:6])
	eth.SrcMAC = net.HardwareAddr(data[6:12])
	eth.EthernetType = EthernetType(binary.BigEndian.Uint16(data[12:14]))
	eth.Length = 0
	if eth.EthernetType < 0x0600 {
		eth.Length = uint16(eth.EthernetType)
		eth.EthernetType = EthernetTypeLLC
	}
	return nil
}

func (eth *Ethernet) bytes() []byte {
	data := make([]byte, EthernetHdrSize)
	copy(data[0:], eth.DstMAC)
	copy(data[6:], eth.SrcMAC)
	copy(data[12:], []byte{0x0000})
	return data
}

type IODevice struct {
	fd              *os.File
	localMacAddress net.HardwareAddr
}

type EthernetFrame struct {
	buffer [MTU]byte
	len    int
}

func (e *EthernetFrame) GetEthernet() (*Ethernet, error) {
	var eth Ethernet
	if len(e.buffer) < EthernetHdrSize {
		return nil, errors.New("Ethernet packet too small")
	}
	eth.DstMAC = net.HardwareAddr(e.buffer[0:6])
	eth.SrcMAC = net.HardwareAddr(e.buffer[6:12])
	eth.EthernetType = EthernetType(binary.BigEndian.Uint16(e.buffer[12:14]))
	eth.Length = 0
	if eth.EthernetType < 0x0600 {
		eth.Length = uint16(eth.EthernetType)
		eth.EthernetType = EthernetTypeLLC
	}
	return &eth, nil
}

func (e *EthernetFrame) GetIP() (*ipv4.Header, error) {
	var ip ipv4.Header
	if len(e.buffer) < EthernetHdrSize+IPHdrSize {
		return nil, errors.New("Ethernet packet too smal")
	}
	ip.Parse(e.buffer[EthernetHdrSize:])
	return &ip, nil
}

func (e *EthernetFrame) Len() int {
	return e.len
}

func (e *EthernetFrame) RawIP() []byte {
	return e.buffer[EthernetHdrSize:e.len]
}

func (io *IODevice) ReadEthFrame() (*EthernetFrame, error) {
	var frame EthernetFrame
	n, e := io.fd.Read(frame.buffer[:])
	fmt.Println("Leido: ", n)
	if e != nil {
		return nil, e
	}
	frame.len = n
	return &frame, nil
}

func (io *IODevice) WriteRawIP(pkt []byte) (int, error) {
	var ip ipv4.Header
	ip.Parse(pkt)
	fmt.Println("Original len: ", len(pkt), ip.String())
	buf := make([]byte, EthernetHdrSize+len(pkt))
	copy(buf, io.localMacAddress)
	copy(buf[EthernetHdrSize:], pkt)
	return io.fd.Write(buf)
}

func UlanDriver() (*IODevice, error) {
	file, err := os.OpenFile("/dev/ulan_io", os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	return &IODevice{
		fd: file,
	}, nil
}
