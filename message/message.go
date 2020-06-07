package message

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

var (
	ErrInvalidAppType = errors.New("invalid appType")
	ErrInvalidMessage = errors.New("invalid message")
	ErrBufferTooSmall = errors.New("buffer is too small for message")
)

const (
	MaxSize    = 2<<15 - 1
	HeaderSize = 2 + 2
)

type Header struct {
	Size uint16
	Type Type
}

func (hdr *Header) Parse(data []byte) (err error) {
	if len(data) < HeaderSize {
		err = ErrInvalidMessage
		return
	}

	hdr.Size = binary.BigEndian.Uint16(data[0:])
	hdr.Type = Type(binary.BigEndian.Uint16(data[2:4]))
	return
}

func (hdr *Header) Read(rd io.Reader) (err error) {
	var header [HeaderSize]byte
	_, err = io.ReadFull(rd, header[:])
	if err != nil {
		return
	}

	hdr.Size = binary.BigEndian.Uint16(header[0:])
	hdr.Type = Type(binary.BigEndian.Uint16(header[2:]))
	return
}

func (hdr *Header) Pack(buf []byte) {
	binary.BigEndian.PutUint16(buf, hdr.Size)
	binary.BigEndian.PutUint16(buf[2:], uint16(hdr.Type))
}

func PackMessage(buf []byte, msg Message) (n int, err error) {
	n = msg.PackedSize() + HeaderSize
	header := Header{uint16(n), msg.Type()}
	header.Pack(buf)
	n2, err := msg.Pack(buf[HeaderSize:])
	if n2+HeaderSize != n && err == nil {
		return -1, ErrInvalidMessage
	}
	return
}

func WriteMessage(wr *bufio.Writer, msg Message) (err error) {
	msgSize := msg.PackedSize() + HeaderSize
	buf := make([]byte, msgSize)
	n, err := PackMessage(buf, msg)
	if err != nil {
		return
	}
	if n != msgSize {
		err = ErrBufferTooSmall
		return
	}

	n, err = wr.Write(buf)
	if n != msgSize {
		err = errors.New("did not send all bytes")
	}

	return
}

type Message interface {
	Type() Type
	Parse(data []byte) error
	Pack(buf []byte) (n int, err error)
	PackedSize() (n int)
}

func readIP(ipv6 bool, data []byte) net.IP {
	if ipv6 {
		return net.IP{
			data[15], data[14], data[13], data[12],
			data[11], data[10], data[9], data[8],
			data[7], data[6], data[5], data[4],
			data[3], data[2], data[1], data[0]}
	}

	return net.IP{data[3], data[2], data[1], data[0]}
}

const flagIPv6 = 1

type portMapping struct {
	app  AppType
	port uint16
}

type portMap []portMapping

// Get returns the port number for the given AppType.
// If no entry is found, 0 is returned.
func (pm portMap) Get(app AppType) (port uint16) {
	for _, mapping := range pm {
		if mapping.app == app {
			return mapping.port
		}
	}
	return 0
}
