package p2p

import (
	"bawang/api"
	"crypto/sha256"
	"encoding/binary"
	"net"
)

const (
	RelayHeaderSize  = 1 + 8 + 2
	MaxRelayDataSize = MaxSize - HeaderSize - RelayHeaderSize
)

// RelayHeader is the header of a relay sub protocol protocol cell
type RelayHeader struct {
	RelayType RelayType
	Size      uint16
	Digest    [8]byte
}

func (hdr *RelayHeader) Parse(data []byte) (err error) {
	if len(data) < HeaderSize {
		err = ErrInvalidMessage
		return
	}
	digestOffset := 3

	hdr.RelayType = RelayType(data[0])
	hdr.Size = binary.BigEndian.Uint16(data[1:3])
	copy(hdr.Digest[:], data[digestOffset:digestOffset+8])
	return
}

func (hdr *RelayHeader) Pack(buf []byte) (err error) {
	if cap(buf) < RelayHeaderSize {
		err = ErrBufferTooSmall
		return
	}
	buf[0] = byte(hdr.RelayType)
	binary.BigEndian.PutUint16(buf[2:4], hdr.Size)

	digestOffset := 3
	copy(buf[digestOffset:digestOffset+8], hdr.Digest[:])

	return
}

func (hdr *RelayHeader) ComputeDigest(msg []byte) (err error) {
	digest := sha256.Sum256(msg)
	for digest[0] != 0x00 && digest[1] != 0x00 {
		digest = sha256.Sum256(msg)
	}
	copy(hdr.Digest[:], digest[:8])
	return
}

func DecryptRelay(buf, msg []byte, key *[32]byte) (ok bool, err error) {
	return false, nil
}

func EncryptRelay(buf, packedMsg []byte, key *[32]byte) (err error) {
	return nil
}

type RelayMessage interface {
	Type() RelayType
	Parse(data []byte) error
	Pack(buf []byte) (n int, err error)
	PackedSize() (n int)
}

// RelayTunnelExtend commands the addressed tunnel hop to extend the tunnel by another hop.
type RelayTunnelExtend struct {
	// TODO: encrypted DH key -> next hop creates TunnelCreate message from it
	IPv6        bool
	Port        uint16
	Address     net.IP
	EncDHPubKey [32]byte // encrypted with peer pub key
}

func (msg *RelayTunnelExtend) Type() RelayType {
	return RelayTypeTunnelExtend
}

func (msg *RelayTunnelExtend) Parse(data []byte) (err error) {
	const minSize = 32 + 2 + 2 + 4
	if len(data) < minSize {
		return ErrInvalidMessage
	}

	msg.IPv6 = data[1]&1 > 0
	msg.Port = binary.BigEndian.Uint16(data[32+2 : 32+2+2])

	// read IP address (either 4 bytes if IPv4 or 16 bytes if IPv6)
	keyOffset := 8
	if msg.IPv6 {
		keyOffset = 20
		if len(data) < keyOffset+32 {
			return ErrInvalidMessage
		}
		msg.Address = api.ReadIP(true, data[4:20])
	} else {
		msg.Address = api.ReadIP(false, data[4:8])
	}

	// must make a copy!
	copy(msg.EncDHPubKey[:], data[keyOffset:keyOffset+32])

	return
}

func (msg *RelayTunnelExtend) PackedSize() (n int) {
	n = 2 + 2 + 4 + len(msg.EncDHPubKey)
	if msg.IPv6 {
		n += 12
	}
	return
}

func (msg *RelayTunnelExtend) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	buf = buf[0:n]

	buf[0] = 0x00 // reserved
	// flags (set later)
	binary.BigEndian.PutUint16(buf[2:4], msg.Port)

	flags := byte(0x00)
	addr := msg.Address
	keyOffset := 8
	if msg.IPv6 {
		keyOffset = 20
		flags |= 1
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

	copy(buf[keyOffset:], msg.EncDHPubKey[:])

	return n, nil
}

type RelayTunnelExtended struct {
	EncDHPubKey      [32]byte // encrypted pub key of next peer
	EncSharedKeyHash [32]byte
}

func (msg *RelayTunnelExtended) Type() RelayType {
	return RelayTypeTunnelExtended
}

func (msg *RelayTunnelExtended) Parse(data []byte) (err error) {
	const size = 32 + 32
	if len(data) < size {
		return ErrInvalidMessage
	}

	copy(msg.EncDHPubKey[:], data[:32])
	copy(msg.EncSharedKeyHash[:], data[32:64])

	return
}

func (msg *RelayTunnelExtended) PackedSize() (n int) {
	n = 32 + 32
	return
}

func (msg *RelayTunnelExtended) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	buf = buf[:n]

	copy(buf[:32], msg.EncDHPubKey[:])
	copy(buf[32:], msg.EncSharedKeyHash[:])

	return
}

// RelayTunnelData is encrypted data
// TODO: wrapped in a relay packet between hops
type RelayTunnelData struct {
	Data []byte
}

func (msg *RelayTunnelData) Type() RelayType {
	return RelayTypeTunnelData
}

func (msg *RelayTunnelData) Parse(data []byte) (err error) {
	// TODO
	return
}

func (msg *RelayTunnelData) PackedSize() (n int) {
	n = len(msg.Data)
	return
}

func (msg *RelayTunnelData) Pack(buf []byte) (n int, err error) {
	// TODO
	return
}
