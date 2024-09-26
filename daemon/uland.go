package main

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
	UTUNTypePing = 0x01
	UTUNTypePong = 0x02
	UTUNTypeDhca = 0x03 // Dynamic Host Configuration Address
	UTUNTypeAddr = 0x04
	UTUNTypeTpdu = 0x05
)

const HDRSZ = 14

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

type UTUNPacket struct {
	MsgType uint8            // 1
	reserve uint8            // 1 Always 0
	MsgLen  uint16           // 2 (Total Length After the header)
	PPSeqN  uint32           // 2
	IfAddr  uint32           // 4
	IfMask  uint32           // 4
	SrcMac  net.HardwareAddr // 6
	Payload []byte
}

func (pkt *UTUNPacket) SerializePayload() error {
	if len(pkt.Payload) < 14 {
		return fmt.Errorf("invalid payload len, must be 14 bytes at least")
	}

	if pkt.MsgType == 0 {
		return fmt.Errorf("invalid message type")
	}

	pkt.Payload[1] = 0
	binary.BigEndian.PutUint16(pkt.Payload[2:], pkt.MsgLen)
	switch pkt.MsgType {
	case UTUNTypePing:
		pkt.Payload[0] = UTUNTypePing
		binary.BigEndian.PutUint32(pkt.Payload[4:], pkt.PPSeqN) // Seq Number
	case UTUNTypePong:
		pkt.Payload[0] = UTUNTypePing
		binary.BigEndian.PutUint32(pkt.Payload[4:], pkt.PPSeqN) // Seq Number
	case UTUNTypeAddr:
		pkt.Payload[0] = UTUNTypeAddr
		binary.BigEndian.PutUint32(pkt.Payload[4:], pkt.IfAddr) // Ip Address
		binary.BigEndian.PutUint32(pkt.Payload[8:], pkt.IfMask) // Mask Address
	case UTUNTypeTpdu:
		pkt.Payload[0] = UTUNTypeTpdu
		copy(pkt.Payload[4:], pkt.SrcMac)
	case UTUNTypeDhca:
		pkt.Payload[0] = UTUNTypeDhca
	}
	return nil
}

func (pkt *UTUNPacket) ParsePayload() error {
	if len(pkt.Payload) < 14 {
		return fmt.Errorf("invalid pkt.Payload len, must be 14 bytes at least")
	}
	pkt.MsgType = pkt.Payload[0]
	pkt.MsgLen = binary.BigEndian.Uint16(pkt.Payload[2:])
	switch pkt.MsgType {
	case UTUNTypePing:
		pkt.PPSeqN = binary.BigEndian.Uint32(pkt.Payload[4:])
	case UTUNTypePong:
		pkt.PPSeqN = binary.BigEndian.Uint32(pkt.Payload[4:])
	case UTUNTypeAddr:
		pkt.IfAddr = binary.BigEndian.Uint32(pkt.Payload[4:])
		pkt.IfMask = binary.BigEndian.Uint32(pkt.Payload[8:])
	case UTUNTypeTpdu:
		copy(pkt.SrcMac, pkt.Payload[4:10])
	case UTUNTypeDhca:
	default:
		return fmt.Errorf("invalid type")
	}
	return nil
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

func (eth *Ethernet) serialize(data []byte) {
	copy(data[0:], eth.DstMAC)
	copy(data[6:], eth.SrcMAC)
	copy(data[12:], []byte{0x0000})
}

type IODevice struct {
	fd              *os.File
	localMacAddress net.HardwareAddr
}

type EthernetFrame struct {
	Eth    Ethernet
	IPv4   ipv4.Header
	len    int
	buffer []byte
}

func (ef *EthernetFrame) Len() int {
	return ef.len
}

func (io *IODevice) ReadFrame() (*EthernetFrame, error) {
	var frame EthernetFrame
	frame.buffer = make([]byte, 1472)
	n, e := io.fd.Read(frame.buffer)
	if e != nil {
		return nil, e
	}
	e = frame.Eth.decodeFromBytes(frame.buffer)
	if e != nil {
		return nil, e
	}

	if frame.Eth.SrcMAC.String() != io.localMacAddress.String() {
		return nil, fmt.Errorf("invalid address")
	}
	e = frame.IPv4.Parse(frame.buffer[14:])
	if e != nil {
		return nil, e
	}
	frame.len = n
	return &frame, nil
}

func (io *IODevice) WriteFrame(frame *EthernetFrame) (int, error) {
	frame.Eth.serialize(frame.buffer[0:14])
	return io.fd.Write(frame.buffer[0:frame.len])
}

func main() {
	file, err := os.Open("/dev/ulan_io")
	if err != nil {
		fmt.Println("error opening device: %v", err)
	}
	defer file.Close()

	for {
		pkt, _ := ReadFrom(file)
		fmt.Println(pkt.Len())
		fmt.Println(pkt.Eth)
		fmt.Println(pkt.IPv4.String())
	}
}
