package message

import (
	"encoding/binary"
	"net"
)

type OnionTunnelBuild struct {
	IPv6        bool
	OnionPort   uint16
	Address     net.IP
	DestHostKey []byte
}

func (msg *OnionTunnelBuild) Type() Type {
	return TypeOnionTunnelBuild
}

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
		msg.Address = readIP(true, data[4:])
	} else {
		msg.Address = readIP(false, data[4:])
	}

	// must make a copy!
	msg.DestHostKey = append(msg.DestHostKey[0:0], data[keyOffset:]...)

	return
}

func (msg *OnionTunnelBuild) PackedSize() (n int) {
	n = 1 + 1 + 2 + 4 + len(msg.DestHostKey)
	if msg.IPv6 {
		n += 12
	}
	return
}

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

type OnionTunnelReady struct {
	TunnelID    uint32
	DestHostKey []byte
}

func (msg *OnionTunnelReady) Type() Type {
	return TypeOnionTunnelReady
}

func (msg *OnionTunnelReady) Parse(data []byte) (err error) {
	if len(data) < 4 {
		return ErrInvalidMessage
	}
	msg.TunnelID = binary.BigEndian.Uint32(data)

	// must make a copy!
	msg.DestHostKey = append(msg.DestHostKey[0:0], data[4:]...)

	return
}

func (msg *OnionTunnelReady) PackedSize() (n int) {
	n = 4 + len(msg.DestHostKey)
	return
}

func (msg *OnionTunnelReady) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf, msg.TunnelID)
	copy(buf[4:], msg.DestHostKey)
	return
}

type OnionTunnelIncoming struct {
	TunnelID uint32
}

func (msg *OnionTunnelIncoming) Type() Type {
	return TypeOnionTunnelIncoming
}

func (msg *OnionTunnelIncoming) Parse(data []byte) (err error) {
	if len(data) != 4 {
		return ErrInvalidMessage
	}
	msg.TunnelID = binary.BigEndian.Uint32(data)
	return
}

func (msg *OnionTunnelIncoming) PackedSize() (n int) {
	n = 4
	return
}

func (msg *OnionTunnelIncoming) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf, msg.TunnelID)
	return n, nil
}

type OnionTunnelDestroy struct {
	TunnelID uint32
}

func (msg *OnionTunnelDestroy) Type() Type {
	return TypeOnionTunnelDestroy
}

func (msg *OnionTunnelDestroy) Parse(data []byte) (err error) {
	if len(data) != 4 {
		return ErrInvalidMessage
	}
	msg.TunnelID = binary.BigEndian.Uint32(data)
	return
}

func (msg *OnionTunnelDestroy) PackedSize() (n int) {
	n = 4
	return
}

func (msg *OnionTunnelDestroy) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf, msg.TunnelID)
	return n, nil
}

type OnionTunnelData struct {
	TunnelID uint32
	Data     []byte
}

func (msg *OnionTunnelData) Type() Type {
	return TypeOnionTunnelData
}

func (msg *OnionTunnelData) Parse(data []byte) (err error) {
	if len(data) < 4 {
		return ErrInvalidMessage
	}
	msg.TunnelID = binary.BigEndian.Uint32(data)

	// must make a copy!
	msg.Data = append(msg.Data[0:0], data[4:]...)
	return
}

func (msg *OnionTunnelData) PackedSize() (n int) {
	n = 4 + len(msg.Data)
	return
}

func (msg *OnionTunnelData) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf, msg.TunnelID)
	copy(buf[4:], msg.Data)
	return
}

type OnionError struct {
	RequestType Type
	TunnelID    uint32
}

func (msg *OnionError) Type() Type {
	return TypeOnionError
}

func (msg *OnionError) Parse(data []byte) (err error) {
	if len(data) != 8 {
		return ErrInvalidMessage
	}
	msg.RequestType = Type(binary.BigEndian.Uint16(data))
	msg.TunnelID = binary.BigEndian.Uint32(data[4:])
	return
}

func (msg *OnionError) PackedSize() (n int) {
	n = 8
	return
}

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

type OnionCover struct {
	CoverSize uint16
}

func (msg *OnionCover) Type() Type {
	return TypeOnionCover
}

func (msg *OnionCover) Parse(data []byte) (err error) {
	if len(data) != 4 {
		return ErrInvalidMessage
	}
	msg.CoverSize = binary.BigEndian.Uint16(data)
	return
}

func (msg *OnionCover) PackedSize() (n int) {
	n = 4
	return
}

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

type OnionPeerCreate struct {
	TunnelID uint16
}

func (msg *OnionPeerCreate) Type() Type {
	return TypeOnionPeerCreate
}

func (msg *OnionPeerCreate) Parse(data []byte) (err error) {
	return
}

func (msg *OnionPeerCreate) PackedSize() (n int) {
	return
}

func (msg *OnionPeerCreate) Pack(buf []byte) (n int, err error) {
	return n, nil
}

type OnionPeerCreated struct {
	TunnelID uint16
}

func (msg *OnionPeerCreated) Type() Type {
	return TypeOnionPeerCreated
}

func (msg *OnionPeerCreated) Parse(data []byte) (err error) {
	return
}

func (msg *OnionPeerCreated) PackedSize() (n int) {
	return
}

func (msg *OnionPeerCreated) Pack(buf []byte) (n int, err error) {
	return n, nil
}

type OnionPeerExtend struct {
	TunnelID uint16
}

func (msg *OnionPeerExtend) Type() Type {
	return TypeOnionPeerExtend
}

func (msg *OnionPeerExtend) Parse(data []byte) (err error) {
	return
}

func (msg *OnionPeerExtend) PackedSize() (n int) {
	return
}

func (msg *OnionPeerExtend) Pack(buf []byte) (n int, err error) {
	return n, nil
}

type OnionPeerExtended struct {
	TunnelID uint16
}

func (msg *OnionPeerExtended) Type() Type {
	return TypeOnionPeerExtended
}

func (msg *OnionPeerExtended) Parse(data []byte) (err error) {
	return
}

func (msg *OnionPeerExtended) PackedSize() (n int) {
	return
}

func (msg *OnionPeerExtended) Pack(buf []byte) (n int, err error) {
	return n, nil
}

type OnionPeerRelay struct {
	TunnelID uint16
}

func (msg *OnionPeerRelay) Type() Type {
	return TypeOnionPeerRelay
}

func (msg *OnionPeerRelay) Parse(data []byte) (err error) {
	return
}

func (msg *OnionPeerRelay) PackedSize() (n int) {
	return
}

func (msg *OnionPeerRelay) Pack(buf []byte) (n int, err error) {
	return n, nil
}

type OnionPeerData struct {
	TunnelID uint16
}

func (msg *OnionPeerData) Type() Type {
	return TypeOnionPeerData
}

func (msg *OnionPeerData) Parse(data []byte) (err error) {
	return
}

func (msg *OnionPeerData) PackedSize() (n int) {
	return
}

func (msg *OnionPeerData) Pack(buf []byte) (n int, err error) {
	return n, nil
}

type OnionPeerDestroy struct {
	TunnelID uint16
}

func (msg *OnionPeerDestroy) Type() Type {
	return TypeOnionPeerDestroy
}

func (msg *OnionPeerDestroy) Parse(data []byte) (err error) {
	return
}

func (msg *OnionPeerDestroy) PackedSize() (n int) {
	return
}

func (msg *OnionPeerDestroy) Pack(buf []byte) (n int, err error) {
	return n, nil
}
