package api

import (
	"encoding/binary"
	"net"
)

// RPSQuery is used to ask RPS to reply with a random peer.
type RPSQuery struct {
}

// Type returns the type of the message.
func (msg *RPSQuery) Type() Type {
	return TypeRPSQuery
}

// Parse fills the struct with values parsed from the given bytes slice.
func (msg *RPSQuery) Parse(data []byte) (err error) {
	return
}

// PackedSize returns the number of bytes required if serialized to bytes.
func (msg *RPSQuery) PackedSize() (n int) {
	n = 0
	return
}

// Pack serializes the values into a bytes slice.
func (msg *RPSQuery) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	return n, nil
}

// RPSPeer is sent by the RPS module as a response to the RPS QUERY message.
type RPSPeer struct {
	Port        uint16
	IPv6        bool
	PortMap     portMap
	Address     net.IP
	DestHostKey []byte
}

// Type returns the type of the message.
func (msg *RPSPeer) Type() Type {
	return TypeRPSPeer
}

// Parse fills the struct with values parsed from the given bytes slice.
func (msg *RPSPeer) Parse(data []byte) (err error) {
	var minSize = 2 + 1 + 1 + 4
	if len(data) < minSize {
		return ErrInvalidMessage
	}

	msg.Port = binary.BigEndian.Uint16(data)

	portMapLen := data[2]
	minSize += int(portMapLen) * 4

	msg.IPv6 = data[3]&flagIPv6 > 0
	if msg.IPv6 {
		minSize += 12
	}

	if len(data) < minSize {
		return ErrInvalidMessage
	}

	offset := 4
	msg.PortMap = make(portMap, portMapLen)
	for i := uint8(0); i < portMapLen; i++ {
		at := AppType(binary.BigEndian.Uint16(data[offset:]))
		if !at.valid() {
			return ErrInvalidAppType
		}
		msg.PortMap[i].app = at
		offset += 2
		msg.PortMap[i].port = binary.BigEndian.Uint16(data[offset:])
		offset += 2
	}

	// read IP address (either 4 bytes if IPv4 or 16 bytes if IPv6)
	if msg.IPv6 {
		msg.Address = ReadIP(true, data[offset:])
		offset += 16
	} else {
		msg.Address = ReadIP(false, data[offset:])
		offset += 4
	}

	// must make a copy!
	msg.DestHostKey = append(msg.DestHostKey[0:0], data[offset:]...)

	return nil
}

// PackedSize returns the number of bytes required if serialized to bytes.
func (msg *RPSPeer) PackedSize() (n int) {
	n = 2 + 1 + 1 + len(msg.PortMap)*4 + 4 + len(msg.DestHostKey)
	if msg.IPv6 {
		n += 12
	}
	return n
}

// Pack serializes the values into a bytes slice.
func (msg *RPSPeer) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	buf = buf[0:n]

	binary.BigEndian.PutUint16(buf, msg.Port)
	buf[2] = uint8(len(msg.PortMap))

	flags := byte(0x00)
	if msg.IPv6 {
		flags |= flagIPv6
	}
	buf[3] = flags

	offset := 4
	for _, mapping := range msg.PortMap {
		if !mapping.app.valid() {
			return -1, ErrInvalidAppType
		}
		binary.BigEndian.PutUint16(buf[offset:], uint16(mapping.app))
		offset += 2
		binary.BigEndian.PutUint16(buf[offset:], mapping.port)
		offset += 2
	}

	addr := msg.Address
	if msg.IPv6 {
		for i := 0; i < 16; i++ {
			buf[offset] = addr[15-i]
			offset++
		}
	} else {
		buf[offset] = addr[3]
		buf[offset+1] = addr[2]
		buf[offset+2] = addr[1]
		buf[offset+3] = addr[0]
		offset += 4
	}

	copy(buf[offset:], msg.DestHostKey)
	return n, nil
}
