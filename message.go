package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

type msgType uint16

//nolint:deadcode,unused,varcheck
const (
	msgTypeGossipAnnounce     msgType = 500
	msgTypeGossipNotify       msgType = 501
	msgTypeGossipNotification msgType = 502
	msgTypeGossipValidation   msgType = 503
	// gossip reserved until 519

	msgTypeNSEQuery    msgType = 520
	msgTypeNSEEstimate msgType = 521
	// NSE reserved until 539

	msgTypeRPSQuery msgType = 540
	msgTypeRPSPeer  msgType = 541
	// RPS reserved until 559

	msgTypeOnionTunnelBuild    msgType = 560
	msgTypeOnionTunnelReady    msgType = 561
	msgTypeOnionTunnelIncoming msgType = 562
	msgTypeOnionTunnelDestroy  msgType = 563
	msgTypeOnionTunnelData     msgType = 564
	msgTypeOnionError          msgType = 565
	msgTypeOnionCover          msgType = 566
	// Onion reserved until 599

	msgTypeAuthSessionStart       msgType = 600
	msgTypeAuthSessionHS1         msgType = 601
	msgTypeAuthSessionIncomingHS1 msgType = 602
	msgTypeAuthSessionHS2         msgType = 603
	msgTypeAuthSessionIncomingHS2 msgType = 604
	msgTypeAuthLayerEncrypt       msgType = 605
	msgTypeAuthLayerDecrypt       msgType = 606
	msgTypeAuthLayerEncryptResp   msgType = 607
	msgTypeAuthLayerDecryptResp   msgType = 608
	msgTypeAuthSessionClose       msgType = 609
	msgTypeAuthError              msgType = 610
	msgTypeAuthCipherEncrypt      msgType = 611
	msgTypeAuthCipherEncryptResp  msgType = 612
	msgTypeAuthCipherDecrypt      msgType = 613
	msgTypeAuthCipherDecryptResp  msgType = 614
	// Onion Auth reserved until 649

	msgDHTPut     msgType = 650
	msgDHTGet     msgType = 651
	msgDHTSuccess msgType = 652
	msgDHTFailure msgType = 653
	// DHT reserved until 679

	msgTypeEnrollInit    msgType = 680
	msgTypeEnrolRegister msgType = 681
	msgTypeEnrolSuccess  msgType = 682
	msgTypeEnrolFailure  msgType = 683
	// Enroll reserved until 689
)

type appType uint16

func (at appType) valid() bool {
	switch at {
	case appTypeDHT,
		appTypeGossip,
		appTypeNSE,
		appTypeOnion:
		return true
	default:
		return false
	}
}

//nolint:deadcode,unused,varcheck
const (
	appTypeDHT    appType = 650
	appTypeGossip appType = 500
	appTypeNSE    appType = 520
	appTypeOnion  appType = 560
)

var (
	errInvalidAppType = errors.New("invalid appType")
	errInvalidMessage = errors.New("invalid message")
	errBufferTooSmall = errors.New("buffer is too small for message")
)

const (
	msgMaxSize    = 2<<15 - 1
	msgHeaderSize = 2 + 2
)

type msgHeader struct {
	Size uint16
	Type msgType
}

func readMsgHeader(rd io.Reader) (hdr msgHeader, err error) {
	var header [msgHeaderSize]byte
	_, err = io.ReadFull(rd, header[:])
	if err != nil {
		return
	}

	hdr.Size = binary.BigEndian.Uint16(header[0:])
	hdr.Type = msgType(binary.BigEndian.Uint16(header[2:]))
	return
}

type message interface {
	Type() msgType
	Parse(data []byte) error
	Pack(buf []byte) (n int, err error)
	PackedSize() (n int)
}

func readIP(ipv6 bool, data []byte) net.IP {
	if ipv6 {
		return net.IP{
			data[15], data[14], data[13], data[12],
			data[11], data[10], data[9], data[8],
			data[7], data[6], data[5], data[4],
			data[3], data[2], data[1], data[0]}
	} else {
		return net.IP{data[3], data[2], data[1], data[0]}
	}
}

const flagIPv6 = 0b10000000

type msgRPSQuery struct {
}

func (msg *msgRPSQuery) Type() msgType {
	return msgTypeRPSQuery
}

func (msg *msgRPSQuery) Parse(data []byte) (err error) {
	return
}

func (msg *msgRPSQuery) PackedSize() (n int) {
	n = 0
	return
}

func (msg *msgRPSQuery) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	return n, nil
}

type portMapping struct {
	app  appType
	port uint16
}

type portMap []portMapping

type msgRPSPeer struct {
	port        uint16
	ipv6        bool
	portMap     portMap
	address     net.IP
	destHostKey []byte
}

func (msg *msgRPSPeer) Type() msgType {
	return msgTypeRPSPeer
}

func (msg *msgRPSPeer) Parse(data []byte) (err error) {
	var minSize = 2 + 1 + 1 + 4
	if len(data) < minSize {
		return errInvalidMessage
	}

	msg.port = binary.BigEndian.Uint16(data)

	portMapLen := uint8(data[2])
	minSize += int(portMapLen) * 4

	msg.ipv6 = data[3]&flagIPv6 > 0
	if msg.ipv6 {
		minSize += 12
	}

	if len(data) < minSize {
		return errInvalidMessage
	}

	offset := 4
	msg.portMap = make(portMap, portMapLen)
	for i := uint8(0); i < portMapLen; i++ {
		msg.portMap[i].app = appType(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		msg.portMap[i].port = binary.BigEndian.Uint16(data[offset:])
		offset += 2
	}

	// read IP address (either 4 bytes if IPv4 or 16 bytes if IPv6)
	if msg.ipv6 {
		msg.address = readIP(true, data[offset:])
		offset += 16
	} else {
		msg.address = readIP(false, data[offset:])
		offset += 4
	}

	// must make a copy!
	msg.destHostKey = append(msg.destHostKey[0:0], data[offset:]...)

	return
}

func (msg *msgRPSPeer) PackedSize() (n int) {
	n = 2 + 1 + 1 + len(msg.portMap)*4 + 4 + len(msg.destHostKey)
	if msg.ipv6 {
		n += 12
	}
	return
}

func (msg *msgRPSPeer) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, errBufferTooSmall
	}
	buf = buf[0:n]

	binary.BigEndian.PutUint16(buf, msg.port)
	buf[2] = uint8(len(msg.portMap))

	flags := byte(0x00)
	if msg.ipv6 {
		flags |= flagIPv6
	}
	buf[3] = flags

	offset := 4
	for _, mapping := range msg.portMap {
		if !mapping.app.valid() {
			return -1, errInvalidAppType
		}
		binary.BigEndian.PutUint16(buf[offset:], uint16(mapping.app))
		offset += 2
		binary.BigEndian.PutUint16(buf[offset:], mapping.port)
		offset += 2
	}

	addr := msg.address
	if msg.ipv6 {
		for i := 0; i < 16; i++ {
			buf[offset] = addr[15-i]
			offset += 1
		}
	} else {
		buf[offset] = addr[3]
		buf[offset+1] = addr[2]
		buf[offset+2] = addr[1]
		buf[offset+3] = addr[0]
		offset += 4
	}

	copy(buf[offset:], msg.destHostKey)
	return n, nil
}

type msgOnionTunnelBuild struct {
	ipv6        bool
	onionPort   uint16
	address     net.IP
	destHostKey []byte
}

func (msg *msgOnionTunnelBuild) Type() msgType {
	return msgTypeOnionTunnelBuild
}

func (msg *msgOnionTunnelBuild) Parse(data []byte) (err error) {
	const minSize = 2 + 2 + 4
	if len(data) < minSize {
		return errInvalidMessage
	}

	msg.ipv6 = data[1]&flagIPv6 > 0
	msg.onionPort = binary.BigEndian.Uint16(data[2:])

	// read IP address (either 4 bytes if IPv4 or 16 bytes if IPv6)
	keyOffset := 8
	if msg.ipv6 {
		keyOffset = 20
		if len(data) < keyOffset {
			return errInvalidMessage
		}
		msg.address = readIP(true, data[4:])
	} else {
		msg.address = readIP(false, data[4:])
	}

	// must make a copy!
	msg.destHostKey = append(msg.destHostKey[0:0], data[keyOffset:]...)

	return
}

func (msg *msgOnionTunnelBuild) PackedSize() (n int) {
	n = 1 + 1 + 2 + 4 + len(msg.destHostKey)
	if msg.ipv6 {
		n += 12
	}
	return
}

func (msg *msgOnionTunnelBuild) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, errBufferTooSmall
	}
	buf = buf[0:n]

	buf[0] = 0x00 // reserved
	// flags (set later)
	binary.BigEndian.PutUint16(buf[2:4], msg.onionPort)

	flags := byte(0x00)
	addr := msg.address
	keyOffset := 8
	if msg.ipv6 {
		keyOffset = 20
		flags |= flagIPv6
		for i := 0; i < 16; i++ {
			buf[4+i] = addr[15-i]
		}
	} else {
		buf[4] = addr[3]
		buf[5] = addr[2]
		buf[6] = addr[1]
		buf[7] = addr[0]
	}
	buf[1] = flags

	copy(buf[keyOffset:], msg.destHostKey)

	return n, nil
}

type msgOnionTunnelReady struct {
	tunnelID    uint32
	destHostKey []byte
}

func (msg *msgOnionTunnelReady) Type() msgType {
	return msgTypeOnionTunnelReady
}

func (msg *msgOnionTunnelReady) Parse(data []byte) (err error) {
	if len(data) < 4 {
		return errInvalidMessage
	}
	msg.tunnelID = binary.BigEndian.Uint32(data)

	// must make a copy!
	msg.destHostKey = append(msg.destHostKey[0:0], data[4:]...)

	return
}

func (msg *msgOnionTunnelReady) PackedSize() (n int) {
	n = 4 + len(msg.destHostKey)
	return
}

func (msg *msgOnionTunnelReady) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, errBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf, msg.tunnelID)
	copy(buf[4:], msg.destHostKey)
	return
}

type msgOnionTunnelIncoming struct {
	tunnelID uint32
}

func (msg *msgOnionTunnelIncoming) Type() msgType {
	return msgTypeOnionTunnelIncoming
}

func (msg *msgOnionTunnelIncoming) Parse(data []byte) (err error) {
	if len(data) != 4 {
		return errInvalidMessage
	}
	msg.tunnelID = binary.BigEndian.Uint32(data)
	return
}

func (msg *msgOnionTunnelIncoming) PackedSize() (n int) {
	n = 4
	return
}

func (msg *msgOnionTunnelIncoming) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, errBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf, msg.tunnelID)
	return n, nil
}

type msgOnionTunnelDestroy struct {
	tunnelID uint32
}

func (msg *msgOnionTunnelDestroy) Type() msgType {
	return msgTypeOnionTunnelDestroy
}

func (msg *msgOnionTunnelDestroy) Parse(data []byte) (err error) {
	if len(data) != 4 {
		return errInvalidMessage
	}
	msg.tunnelID = binary.BigEndian.Uint32(data)
	return
}

func (msg *msgOnionTunnelDestroy) PackedSize() (n int) {
	n = 4
	return
}

func (msg *msgOnionTunnelDestroy) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, errBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf, msg.tunnelID)
	return n, nil
}

type msgOnionTunnelData struct {
	tunnelID uint32
	data     []byte
}

func (msg *msgOnionTunnelData) Type() msgType {
	return msgTypeOnionTunnelData
}

func (msg *msgOnionTunnelData) Parse(data []byte) (err error) {
	if len(data) < 4 {
		return errInvalidMessage
	}
	msg.tunnelID = binary.BigEndian.Uint32(data)

	// must make a copy!
	msg.data = append(msg.data[0:0], data[4:]...)
	return
}

func (msg *msgOnionTunnelData) PackedSize() (n int) {
	n = 4 + len(msg.data)
	return
}

func (msg *msgOnionTunnelData) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, errBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf, msg.tunnelID)
	copy(buf[4:], msg.data)
	return
}

type msgOnionError struct {
	requestType msgType
	tunnelID    uint32
}

func (msg *msgOnionError) Type() msgType {
	return msgTypeOnionError
}

func (msg *msgOnionError) Parse(data []byte) (err error) {
	if len(data) != 8 {
		return errInvalidMessage
	}
	msg.requestType = msgType(binary.BigEndian.Uint16(data))
	msg.tunnelID = binary.BigEndian.Uint32(data[4:])
	return
}

func (msg *msgOnionError) PackedSize() (n int) {
	n = 8
	return
}

func (msg *msgOnionError) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, errBufferTooSmall
	}
	binary.BigEndian.PutUint16(buf, uint16(msg.requestType))
	buf[2] = 0x00
	buf[3] = 0x00
	binary.BigEndian.PutUint32(buf[4:], msg.tunnelID)
	return n, nil
}

type msgOnionCover struct {
	coverSize uint16
}

func (msg *msgOnionCover) Type() msgType {
	return msgTypeOnionCover
}

func (msg *msgOnionCover) Parse(data []byte) (err error) {
	if len(data) != 4 {
		return errInvalidMessage
	}
	msg.coverSize = binary.BigEndian.Uint16(data)
	return
}

func (msg *msgOnionCover) PackedSize() (n int) {
	n = 4
	return
}

func (msg *msgOnionCover) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, errBufferTooSmall
	}
	binary.BigEndian.PutUint16(buf, msg.coverSize)
	buf[2] = 0x00
	buf[3] = 0x00
	return n, nil
}
