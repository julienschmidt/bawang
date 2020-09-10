package p2p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"net"

	"bawang/api"
)

const (
	RelayHeaderSize  = 3 + 1 + 2 + 1 + 8
	MaxRelayDataSize = MaxSize - HeaderSize - RelayHeaderSize
	MaxRelaySize     = MaxSize - HeaderSize
)

type RelayMessage interface {
	Type() RelayType
	Parse(data []byte) error
	Pack(buf []byte) (n int, err error)
	PackedSize() (n int)
}

const flagIPv6 = 1

// RelayHeader is the header of a relay sub protocol protocol cell
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Tunnel ID                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  TUNNEL RELAY |                   Counter                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Relay Type  |             Size              |    Reserved   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Digest (8 byte)                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type RelayHeader struct {
	Counter   [3]byte
	RelayType RelayType
	Size      uint16
	Digest    [8]byte
}

func (hdr *RelayHeader) Parse(data []byte) (err error) {
	if len(data) < RelayHeaderSize {
		return ErrInvalidMessage
	}

	copy(hdr.Counter[:], data[0:3])
	digestOffset := 7

	hdr.RelayType = RelayType(data[3])
	hdr.Size = binary.BigEndian.Uint16(data[4:6])
	copy(hdr.Digest[:], data[digestOffset:digestOffset+8])

	return nil
}

func (hdr *RelayHeader) Pack(buf []byte) (err error) {
	if cap(buf) < RelayHeaderSize {
		return ErrBufferTooSmall
	}
	copy(buf[:3], hdr.Counter[:])
	buf[3] = byte(hdr.RelayType)
	binary.BigEndian.PutUint16(buf[4:6], hdr.Size)

	digestOffset := 7
	copy(buf[digestOffset:digestOffset+8], hdr.Digest[:])

	return nil
}

func (hdr *RelayHeader) ComputeDigest(msg []byte) {
	copy(hdr.Digest[:], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // initialize digest to zero
	packedHdr := make([]byte, RelayHeaderSize)
	fullMsg := append(packedHdr, msg...)

	digest := sha256.Sum256(fullMsg)
	for digest[0] != 0x00 && digest[1] != 0x00 {
		digest = sha256.Sum256(fullMsg)
	}
	copy(hdr.Digest[:], digest[:8])
}

func (hdr *RelayHeader) CheckDigest(msg []byte) (ok bool) {
	if hdr.Digest[0] != 0x00 || hdr.Digest[1] != 0x00 {
		return false
	}

	digest := make([]byte, 8)
	copy(digest, hdr.Digest[:])
	hdr.ComputeDigest(msg)

	ok = true
	for i, v := range digest {
		if v != hdr.Digest[i] {
			ok = false
			break
		}
	}
	copy(hdr.Digest[:], digest)

	return ok
}

func PackRelayMessage(buf []byte, counter uint64, msg RelayMessage) (newCounter uint64, n int, err error) {
	n = msg.PackedSize() + RelayHeaderSize
	if len(buf) < n {
		return counter, -1, ErrBufferTooSmall
	}

	// generate random counter, greater than the previous one
	counter += uint64(rand.Int63n(128))
	byteCounter := make([]byte, 4)
	binary.BigEndian.PutUint64(byteCounter, counter)
	ctr := [3]byte{}
	copy(ctr[:], byteCounter[:3])
	header := RelayHeader{
		Counter:   ctr,
		RelayType: msg.Type(),
		Size:      uint16(msg.PackedSize() + RelayHeaderSize),
	}

	rand.Read(buf[RelayHeaderSize:n]) // initialize the full 512 - HeaderSize bytes of the messages with pseudo randomness
	n2, err := msg.Pack(buf[RelayHeaderSize:])
	if n2+RelayHeaderSize != n && err == nil {
		return counter, -1, ErrInvalidMessage
	}
	header.ComputeDigest(buf[RelayHeaderSize:])

	err = header.Pack(buf[:RelayHeaderSize])
	if err != nil {
		return counter, -1, err
	}

	return counter, n, nil
}

func DecryptRelay(encRelayMsg []byte, key *[32]byte) (ok bool, msg []byte, err error) {
	if len(encRelayMsg) > MaxRelayDataSize+RelayHeaderSize {
		return false, nil, ErrInvalidMessage
	}
	// message starts with the relay message header, we get the counter from the first 3 bytes
	counter := encRelayMsg[:3]
	iv := make([]byte, aes.BlockSize)
	fullDigest := sha256.Sum256(counter)
	copy(iv, fullDigest[:aes.BlockSize])

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return false, nil, err
	}

	msg = make([]byte, len(encRelayMsg))
	copy(msg[:3], counter)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(msg[3:], encRelayMsg[3:])

	hdr := RelayHeader{}
	err = hdr.Parse(msg)
	if err != nil {
		return false, nil, err
	}

	ok = hdr.CheckDigest(msg[RelayHeaderSize:])

	return ok, msg, nil
}

func EncryptRelay(packedMsg []byte, key *[32]byte) (encMsg []byte, err error) {
	counter := packedMsg[:3]
	iv := make([]byte, aes.BlockSize)
	fullCounterDigest := sha256.Sum256(counter)
	copy(iv, fullCounterDigest[:aes.BlockSize])

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	encMsg = make([]byte, len(packedMsg))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(encMsg[3:], packedMsg[3:])

	copy(encMsg[:3], counter)

	return encMsg, nil
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

	msg.IPv6 = data[1]&flagIPv6 > 0
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

	return nil
}

func (msg *RelayTunnelExtend) PackedSize() (n int) {
	n = 2 + 2 + 4 + len(msg.EncDHPubKey)
	if msg.IPv6 {
		n += 12
	}
	return n
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
	DHPubKey      [32]byte // encrypted pub key of next peer
	SharedKeyHash [32]byte
}

func (msg *RelayTunnelExtended) Type() RelayType {
	return RelayTypeTunnelExtended
}

func (msg *RelayTunnelExtended) Parse(data []byte) (err error) {
	const size = 32 + 32
	if len(data) < size {
		return ErrInvalidMessage
	}

	copy(msg.DHPubKey[:], data[:32])
	copy(msg.SharedKeyHash[:], data[32:64])

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

	copy(buf[:32], msg.DHPubKey[:])
	copy(buf[32:], msg.SharedKeyHash[:])

	return n, nil
}

// RelayTunnelData is application payload we receive
type RelayTunnelData struct {
	Data []byte
}

func (msg *RelayTunnelData) Type() RelayType {
	return RelayTypeTunnelData
}

func (msg *RelayTunnelData) Parse(data []byte) (err error) {
	msg.Data = data // TODO: need to copy here?
	return
}

func (msg *RelayTunnelData) PackedSize() (n int) {
	n = len(msg.Data)
	return
}

func (msg *RelayTunnelData) Pack(buf []byte) (n int, err error) {
	if len(buf) < len(msg.Data) {
		err = ErrBufferTooSmall
		return
	}

	copy(buf[:len(msg.Data)], msg.Data)
	n = len(msg.Data)
	return
}
