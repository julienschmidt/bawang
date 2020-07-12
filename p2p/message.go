package p2p

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	HeaderSize = 4 + 1
	MaxSize    = 512
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
	//Size     uint16 // TODO: where to put message length?
}

func (hdr *Header) Parse(data []byte) (err error) {
	if len(data) < HeaderSize {
		err = ErrInvalidMessage
		return
	}

	hdr.TunnelID = binary.BigEndian.Uint32(data)
	hdr.Type = Type(binary.BigEndian.Uint16(data[4:6]))
	return
}

func (hdr *Header) Read(rd io.Reader) (err error) {
	var header [HeaderSize]byte
	_, err = io.ReadFull(rd, header[:])
	if err != nil {
		return
	}

	hdr.TunnelID = binary.BigEndian.Uint32(header[0:])
	hdr.Type = Type(binary.BigEndian.Uint16(header[4:6]))
	return
}

func (hdr *Header) Pack(buf []byte) {
	binary.BigEndian.PutUint32(buf, hdr.TunnelID)
	binary.BigEndian.PutUint16(buf[4:], uint16(hdr.Type))
}

func PackMessage(buf []byte, tunnelID uint32, msg Message) (n int, err error) {
	n = msg.PackedSize() + HeaderSize
	header := Header{tunnelID, msg.Type()}
	header.Pack(buf)
	n2, err := msg.Pack(buf[HeaderSize:])
	if n2+HeaderSize != n && err == nil {
		return -1, ErrInvalidMessage
	}
	return
}
