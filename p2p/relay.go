package p2p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	mathRand "math/rand"
	"net"

	"bawang/api"
)

const (
	RelayHeaderSize  = 3 + 1 + 2 + 1 + 8                  // Relay sub-header size
	RelayMessageSize = MaxBodySize                        // Size of a relay (sub-)message
	MaxRelayDataSize = RelayMessageSize - RelayHeaderSize // Max size of relay payload
)

// RelayMessage abstracts a relay sub protocol protocol message (not containing the outer header).
type RelayMessage interface {
	Type() RelayType                    // Type returns the relay type of the message.
	Parse(data []byte) error            // Parse fills the struct with values parsed from the given bytes slice.
	Pack(buf []byte) (n int, err error) // Pack serializes the values into a bytes slice.
	PackedSize() (n int)                // PackedSize returns the number of bytes required if serialized to bytes.
}

const flagIPv6 = 1

// RelayHeader is the header of a relay sub protocol protocol cell.
type RelayHeader struct {
	Counter   [3]byte
	RelayType RelayType
	Size      uint16
	Digest    [8]byte
}

// GetCounter returns the counter value as uint32
func (hdr *RelayHeader) GetCounter() (ctr uint32) {
	counterBytes := make([]byte, 4)
	copy(counterBytes[1:], hdr.Counter[:])
	ctr = binary.BigEndian.Uint32(counterBytes)

	return ctr
}

// Parse parses a message (sub-)header from the given data.
func (hdr *RelayHeader) Parse(data []byte) (err error) {
	if len(data) < RelayHeaderSize {
		return ErrInvalidMessage
	}

	copy(hdr.Counter[:], data[:3])
	digestOffset := 7

	hdr.RelayType = RelayType(data[3])
	hdr.Size = binary.BigEndian.Uint16(data[4:6])
	copy(hdr.Digest[:], data[digestOffset:digestOffset+8])

	return nil
}

// Pack serializes the header into bytes.
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

// ComputeDigest computes the digest for a given message body and saves it into the header.
func (hdr *RelayHeader) ComputeDigest(body []byte) (err error) {
	copy(hdr.Digest[:], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // initialize digest to zero
	packedHdr := make([]byte, RelayHeaderSize)
	err = hdr.Pack(packedHdr)
	if err != nil {
		return err
	}
	fullMsg := append(packedHdr, body...)

	digest := sha256.Sum256(fullMsg)
	// TODO: figure out how we can reintroduce this quick check
	// for digest[0] != 0x00 && digest[1] != 0x00 {
	// 	digest = sha256.Sum256(fullMsg)
	// }

	copy(hdr.Digest[:], digest[:8])

	return err
}

// CheckDigest verifies that the digest within the header is valid for a given message body.
func (hdr *RelayHeader) CheckDigest(body []byte) (ok bool) {
	// TODO: figure out how we can reintroduce this quick check
	// if hdr.Digest[0] != 0x00 || hdr.Digest[1] != 0x00 {
	// 	return false
	// }

	digest := make([]byte, 8)
	copy(digest, hdr.Digest[:])
	err := hdr.ComputeDigest(body)
	if err != nil {
		copy(hdr.Digest[:], digest)
		return false
	}

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

// PackRelayMessage serializes a given relay message into the given bytes buffer (without outer P2P message header).
func PackRelayMessage(buf []byte, oldCounter uint32, msg RelayMessage) (newCounter uint32, n int, err error) {
	// sanity checks
	n = MaxRelayDataSize + RelayHeaderSize
	if len(buf) < n {
		return oldCounter, -1, ErrBufferTooSmall
	}
	if msg == nil {
		return oldCounter, -1, ErrInvalidMessage
	}

	// generate random  counter, greater than the previous one
	newCounter = oldCounter + uint32(mathRand.Int31n(64)) //nolint:gosec // pseudo-rand is good enough here
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, newCounter)
	hdr := RelayHeader{
		Counter:   [3]byte{counterBytes[1], counterBytes[2], counterBytes[3]},
		RelayType: msg.Type(),
		Size:      uint16(msg.PackedSize() + RelayHeaderSize),
	}

	n2, err := msg.Pack(buf[RelayHeaderSize:])
	if err != nil {
		return newCounter, -1, err
	}
	if n2 != msg.PackedSize() {
		return newCounter, -1, ErrInvalidMessage
	}

	// initialize remaining bytes of the packet with pseudo randomness
	_, err = rand.Read(buf[RelayHeaderSize+n2 : n])
	if err != nil {
		return
	}

	err = hdr.ComputeDigest(buf[RelayHeaderSize:n])
	if err != nil {
		return newCounter, -1, err
	}

	_ = hdr.Pack(buf[:RelayHeaderSize])

	return newCounter, n, nil
}

// DecryptRelay attempts to decrypt an encrypted message given as a bytes slice with a given key.
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

// DecryptRelay encrypts a message given as a bytes slice with the given key.
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
	IPv6        bool
	Port        uint16
	Address     net.IP
	EncDHPubKey [512]byte //  encrypted DH key -> next hop creates TunnelCreate message from it
}

// Type returns the relay type of the message.
func (msg *RelayTunnelExtend) Type() RelayType {
	return RelayTypeTunnelExtend
}

// Parse fills the struct with values parsed from the given bytes slice.
func (msg *RelayTunnelExtend) Parse(data []byte) (err error) {
	const minSize = len(msg.EncDHPubKey) + 2 + 2 + 4
	if len(data) < minSize {
		return ErrInvalidMessage
	}

	msg.IPv6 = data[1]&flagIPv6 > 0
	msg.Port = binary.BigEndian.Uint16(data[2:4])

	// read IP address (either 4 bytes if IPv4 or 16 bytes if IPv6)
	keyOffset := 8
	if msg.IPv6 {
		keyOffset = 20
		if len(data) < keyOffset+len(msg.EncDHPubKey) {
			return ErrInvalidMessage
		}
		msg.Address = api.ReadIP(true, data[4:20])
	} else {
		msg.Address = api.ReadIP(false, data[4:8])
	}

	// must make a copy!
	copy(msg.EncDHPubKey[:], data[keyOffset:keyOffset+len(msg.EncDHPubKey)])

	return nil
}

// PackedSize returns the number of bytes required if serialized to bytes.
func (msg *RelayTunnelExtend) PackedSize() (n int) {
	n = 2 + 2 + 4 + len(msg.EncDHPubKey)
	if msg.IPv6 {
		n += 12
	}
	return n
}

// Pack serializes the values into a bytes slice.
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

	copy(buf[keyOffset:], msg.EncDHPubKey[:])

	return n, nil
}

// RelayTunnelExtended is used to relay the created message from the next hop back to the original sender of the TUNNEL EXTEND message.
type RelayTunnelExtended struct {
	DHPubKey      [32]byte // encrypted pub key of next peer
	SharedKeyHash [32]byte
}

// Type returns the relay type of the message.
func (msg *RelayTunnelExtended) Type() RelayType {
	return RelayTypeTunnelExtended
}

// Parse fills the struct with values parsed from the given bytes slice.
func (msg *RelayTunnelExtended) Parse(data []byte) (err error) {
	const size = 32 + 32
	if len(data) < size {
		return ErrInvalidMessage
	}

	copy(msg.DHPubKey[:], data[:32])
	copy(msg.SharedKeyHash[:], data[32:64])

	return
}

// PackedSize returns the number of bytes required if serialized to bytes.
func (msg *RelayTunnelExtended) PackedSize() (n int) {
	n = 32 + 32
	return
}

// Pack serializes the values into a bytes slice.
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

// RelayTunnelData is application payload we receive.
type RelayTunnelData struct {
	Data []byte
}

// Type returns the relay type of the message.
func (msg *RelayTunnelData) Type() RelayType {
	return RelayTypeTunnelData
}

// Parse fills the struct with values parsed from the given bytes slice.
func (msg *RelayTunnelData) Parse(data []byte) (err error) {
	msg.Data = make([]byte, len(data))
	copy(msg.Data, data)
	return
}

// PackedSize returns the number of bytes required if serialized to bytes.
func (msg *RelayTunnelData) PackedSize() (n int) {
	n = len(msg.Data)
	return
}

// Pack serializes the values into a bytes slice.
func (msg *RelayTunnelData) Pack(buf []byte) (n int, err error) {
	if len(buf) < len(msg.Data) {
		err = ErrBufferTooSmall
		return
	}

	copy(buf[:len(msg.Data)], msg.Data)
	n = len(msg.Data)
	return
}
