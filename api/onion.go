package api

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
)

// OnionTunnelBuild is used to request the Onion module to build a tunnel to the given destination in the next period.
type OnionTunnelBuild struct {
	IPv6        bool
	OnionPort   uint16
	Address     net.IP
	DestHostKey []byte
}

// Type returns the type of the message.
func (msg *OnionTunnelBuild) Type() Type {
	return TypeOnionTunnelBuild
}

// Parse fills the struct with values parsed from the given bytes slice.
func (msg *OnionTunnelBuild) Parse(data []byte) (err error) {
	const minSize = 2 + 2 + 4
	if len(data) < minSize {
		return ErrInvalidMessage
	}

	msg.IPv6 = data[1]&flagIPv6 > 0
	msg.OnionPort = binary.BigEndian.Uint16(data[2:])

	// read IP address (either 4 bytes if IPv4 or 16 bytes if IPv6)
	keyOffset := 8
	if msg.IPv6 {
		keyOffset = 20
		if len(data) < keyOffset {
			return ErrInvalidMessage
		}
		msg.Address = ReadIP(true, data[4:])
	} else {
		msg.Address = ReadIP(false, data[4:])
	}

	// must make a copy!
	msg.DestHostKey = append(msg.DestHostKey[0:0], data[keyOffset:]...)

	return nil
}

// PackedSize returns the number of bytes required if serialized to bytes.
func (msg *OnionTunnelBuild) PackedSize() (n int) {
	n = 1 + 1 + 2 + 4 + len(msg.DestHostKey)
	if msg.IPv6 {
		n += 12
	}
	return
}

// Pack serializes the values into a bytes slice.
func (msg *OnionTunnelBuild) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	buf = buf[0:n]

	buf[0] = 0x00 // reserved
	// flags (set later)
	binary.BigEndian.PutUint16(buf[2:4], msg.OnionPort)

	flags := byte(0x00)
	addr := msg.Address
	keyOffset := 8
	if msg.IPv6 {
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

	copy(buf[keyOffset:], msg.DestHostKey)

	return n, nil
}

// ParseHostKey parses the host key contained in the message as a RSA public key.
func (msg *OnionTunnelBuild) ParseHostKey() (key *rsa.PublicKey, err error) {
	key, err = x509.ParsePKCS1PublicKey(msg.DestHostKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hostkey: %v", err)
	}
	return key, nil
}

// OnionTunnelReady is sent by the Onion module when a requested tunnel is built.
type OnionTunnelReady struct {
	TunnelID    uint32
	DestHostKey []byte
}

// Type returns the type of the message.
func (msg *OnionTunnelReady) Type() Type {
	return TypeOnionTunnelReady
}

// Parse fills the struct with values parsed from the given bytes slice.
func (msg *OnionTunnelReady) Parse(data []byte) (err error) {
	if len(data) < 4 {
		return ErrInvalidMessage
	}
	msg.TunnelID = binary.BigEndian.Uint32(data)

	// must make a copy!
	msg.DestHostKey = append(msg.DestHostKey[0:0], data[4:]...)

	return
}

// PackedSize returns the number of bytes required if serialized to bytes.
func (msg *OnionTunnelReady) PackedSize() (n int) {
	n = 4 + len(msg.DestHostKey)
	return
}

// Pack serializes the values into a bytes slice.
func (msg *OnionTunnelReady) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf, msg.TunnelID)
	copy(buf[4:], msg.DestHostKey)
	return
}

// OnionTunnelIncoming is sent by the Onion module on all of its API connections to signal a new incoming tunnel connection.
type OnionTunnelIncoming struct {
	TunnelID uint32
}

// Type returns the type of the message.
func (msg *OnionTunnelIncoming) Type() Type {
	return TypeOnionTunnelIncoming
}

// Parse fills the struct with values parsed from the given bytes slice.
func (msg *OnionTunnelIncoming) Parse(data []byte) (err error) {
	if len(data) != 4 {
		return ErrInvalidMessage
	}
	msg.TunnelID = binary.BigEndian.Uint32(data)
	return
}

// PackedSize returns the number of bytes required if serialized to bytes.
func (msg *OnionTunnelIncoming) PackedSize() (n int) {
	n = 4
	return
}

// Pack serializes the values into a bytes slice.
func (msg *OnionTunnelIncoming) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf, msg.TunnelID)
	return n, nil
}

// OnionTunnelDestroy is used to instruct the Onion module that a tunnel it created is no longer in use and can now be destroyed.
type OnionTunnelDestroy struct {
	TunnelID uint32
}

// Type returns the type of the message.
func (msg *OnionTunnelDestroy) Type() Type {
	return TypeOnionTunnelDestroy
}

// Parse fills the struct with values parsed from the given bytes slice.
func (msg *OnionTunnelDestroy) Parse(data []byte) (err error) {
	if len(data) != 4 {
		return ErrInvalidMessage
	}
	msg.TunnelID = binary.BigEndian.Uint32(data)
	return
}

// PackedSize returns the number of bytes required if serialized to bytes.
func (msg *OnionTunnelDestroy) PackedSize() (n int) {
	n = 4
	return
}

// Pack serializes the values into a bytes slice.
func (msg *OnionTunnelDestroy) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf, msg.TunnelID)
	return n, nil
}

// OnionTunnelData is used to ask the Onion module to forward data through a tunnel.
type OnionTunnelData struct {
	TunnelID uint32
	Data     []byte
}

// Type returns the type of the message.
func (msg *OnionTunnelData) Type() Type {
	return TypeOnionTunnelData
}

// Parse fills the struct with values parsed from the given bytes slice.
func (msg *OnionTunnelData) Parse(data []byte) (err error) {
	if len(data) < 4 {
		return ErrInvalidMessage
	}
	msg.TunnelID = binary.BigEndian.Uint32(data)

	// must make a copy!
	msg.Data = append(msg.Data[0:0], data[4:]...)
	return
}

// PackedSize returns the number of bytes required if serialized to bytes.
func (msg *OnionTunnelData) PackedSize() (n int) {
	n = 4 + len(msg.Data)
	return
}

// Pack serializes the values into a bytes slice.
func (msg *OnionTunnelData) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf, msg.TunnelID)
	copy(buf[4:], msg.Data)
	return
}

// OnionError is sent by the Onion module to signal an error condition
// which stems from servicing an earlier request.
type OnionError struct {
	RequestType Type
	TunnelID    uint32
}

// Type returns the type of the message.
func (msg *OnionError) Type() Type {
	return TypeOnionError
}

// Parse fills the struct with values parsed from the given bytes slice.
func (msg *OnionError) Parse(data []byte) (err error) {
	if len(data) != 8 {
		return ErrInvalidMessage
	}
	msg.RequestType = Type(binary.BigEndian.Uint16(data))
	msg.TunnelID = binary.BigEndian.Uint32(data[4:])
	return
}

// PackedSize returns the number of bytes required if serialized to bytes.
func (msg *OnionError) PackedSize() (n int) {
	n = 8
	return
}

// Pack serializes the values into a bytes slice.
func (msg *OnionError) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	binary.BigEndian.PutUint16(buf, uint16(msg.RequestType))
	buf[2] = 0x00
	buf[3] = 0x00
	binary.BigEndian.PutUint32(buf[4:], msg.TunnelID)
	return n, nil
}

// OnionCover instructs the onion module to send cover traffic to a random destination.
type OnionCover struct {
	CoverSize uint16
}

// Type returns the type of the message.
func (msg *OnionCover) Type() Type {
	return TypeOnionCover
}

// Parse fills the struct with values parsed from the given bytes slice.
func (msg *OnionCover) Parse(data []byte) (err error) {
	if len(data) != 4 {
		return ErrInvalidMessage
	}
	msg.CoverSize = binary.BigEndian.Uint16(data)
	return
}

// PackedSize returns the number of bytes required if serialized to bytes.
func (msg *OnionCover) PackedSize() (n int) {
	n = 4
	return
}

// Pack serializes the values into a bytes slice.
func (msg *OnionCover) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	binary.BigEndian.PutUint16(buf, msg.CoverSize)
	buf[2] = 0x00
	buf[3] = 0x00
	return n, nil
}
