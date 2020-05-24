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

	msgTypeRSPQuery msgType = 540
	msgTypeRSPPeer  msgType = 541
	// RSP reserved until 559

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

var (
	errInvalidMessage = errors.New("invalid message")
	errBufferTooSmall = errors.New("buffer is too small for message")
)

const msgHeaderSize = 2 + 2

type msgHeader struct {
	Size uint16
	Type msgType
}

func readMsgHeader(rd io.Reader) (hdr msgHeader, err error) {
	var header [msgHeaderSize]byte
	_, err = rd.Read(header[:])
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

const flagIPv6 = 0b10000000

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
		msg.address = net.IP{
			data[19], data[18], data[17], data[16],
			data[15], data[14], data[13], data[12],
			data[11], data[10], data[9], data[8],
			data[7], data[6], data[5], data[4]}
	} else {
		msg.address = net.IP{data[7], data[6], data[5], data[4]}
	}

	// must make a copy!
	msg.destHostKey = append(msg.destHostKey[0:0], data[keyOffset:]...)

	return
}

func (msg *msgOnionTunnelBuild) PackedSize() (n int) {
	n = 1 + 1 + 2 + 4
	if msg.ipv6 {
		n += 12
	}
	n += len(msg.destHostKey)
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
