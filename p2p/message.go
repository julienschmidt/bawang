package p2p

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	HeaderSize  = 4 + 1                    // Size of a P2P header
	MessageSize = 1024                     // Size of a P2P packet (static and padded if content is smaller)
	MaxBodySize = MessageSize - HeaderSize // Max size of payload
)

var (
	ErrInvalidMessage = errors.New("invalid message")
	ErrBufferTooSmall = errors.New("buffer is too small for message")
)

// Message abstracts a P2p message.
type Message interface {
	Type() Type                         // Type returns the type of the message.
	Parse(data []byte) error            // Parse fills the struct with values parsed from the given bytes slice.
	Pack(buf []byte) (n int, err error) // Pack serializes the values into a bytes slice.
	PackedSize() (n int)                // PackedSize returns the number of bytes required if serialized to bytes.
}

// Header is the message header of a P2P message.
type Header struct {
	TunnelID uint32
	Type     Type
}

// Parse parses a message header from the given data.
func (hdr *Header) Parse(data []byte) (err error) {
	if len(data) < HeaderSize {
		err = ErrInvalidMessage
		return
	}

	hdr.TunnelID = binary.BigEndian.Uint32(data[:4])
	hdr.Type = Type(data[4])
	return
}

// Read reads and parses a message header from the given reader.
func (hdr *Header) Read(rd io.Reader) (err error) {
	var header [HeaderSize]byte
	_, err = io.ReadFull(rd, header[:])
	if err != nil {
		return
	}

	hdr.TunnelID = binary.BigEndian.Uint32(header[:4])
	hdr.Type = Type(header[4])
	return
}

// Pack serializes the header into bytes.
func (hdr *Header) Pack(buf []byte) {
	binary.BigEndian.PutUint32(buf, hdr.TunnelID)
	buf[4] = uint8(hdr.Type)
}

// PackMessage serializes a given message into the given bytes buffer.
func PackMessage(buf []byte, tunnelID uint32, msg Message) (n int, err error) {
	if msg == nil {
		return -1, ErrInvalidMessage
	}

	n = MessageSize // we always pack the full packet such that we pad accordingly
	header := Header{tunnelID, msg.Type()}
	header.Pack(buf[:HeaderSize])
	n2, err := msg.Pack(buf[HeaderSize:n])
	if err != nil {
		return -1, err
	}
	if n2 != msg.PackedSize() {
		return -1, ErrInvalidMessage
	}

	_, err = rand.Read(buf[HeaderSize+n2 : n]) // initialize remaining bytes of the packet with randomness
	return n, err
}
