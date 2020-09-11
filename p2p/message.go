package p2p

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	HeaderSize     = 4 + 1
	MaxSize        = 1024
	MaxMessageSize = MaxSize - HeaderSize
)

var (
	ErrInvalidMessage = errors.New("invalid message")
	ErrBufferTooSmall = errors.New("buffer is too small for message")
)

type Message interface {
	Type() Type
	Parse(data []byte) error
	Pack(buf []byte) (n int, err error)
	PackedSize() (n int)
}

type Header struct {
	TunnelID uint32
	Type     Type
}

func (hdr *Header) Parse(data []byte) (err error) {
	if len(data) < HeaderSize {
		err = ErrInvalidMessage
		return
	}

	hdr.TunnelID = binary.BigEndian.Uint32(data[:4])
	hdr.Type = Type(data[4])
	return
}

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

func (hdr *Header) Pack(buf []byte) {
	binary.BigEndian.PutUint32(buf, hdr.TunnelID)
	buf[4] = uint8(hdr.Type)
}

func PackMessage(buf []byte, tunnelID uint32, msg Message) (n int, err error) {
	if msg == nil {
		return -1, ErrInvalidMessage
	}

	n = MaxSize // we always pack the full packet such that we pad accordingly
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
