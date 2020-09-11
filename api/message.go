package api

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const (
	MaxSize    = 2<<15 - 1 // Max total size of an API message
	HeaderSize = 2 + 2     // Size of the header of an API message
)

const flagIPv6 = 1

// Message abstracts an API message.
type Message interface {
	Type() Type
	Parse(data []byte) error
	Pack(buf []byte) (n int, err error)
	PackedSize() (n int)
}

var (
	ErrInvalidAppType = errors.New("invalid appType")
	ErrInvalidMessage = errors.New("invalid message")
	ErrBufferTooSmall = errors.New("buffer is too small for message")
)

// Header is the message header of an API message.
type Header struct {
	Size uint16
	Type Type
}

// Parse parses a message header from the given data.
func (hdr *Header) Parse(data []byte) (err error) {
	if len(data) < HeaderSize {
		err = ErrInvalidMessage
		return
	}

	hdr.Size = binary.BigEndian.Uint16(data)
	hdr.Type = Type(binary.BigEndian.Uint16(data[2:4]))
	return
}

// Read reads and parses a message header from the given reader.
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

// Pack serializes the header into bytes.
func (hdr *Header) Pack(buf []byte) {
	binary.BigEndian.PutUint16(buf, hdr.Size)
	binary.BigEndian.PutUint16(buf[2:], uint16(hdr.Type))
}

// PackMessage serializes a given message into the given bytes buffer.
func PackMessage(buf []byte, msg Message) (n int, err error) {
	if msg == nil {
		return -1, ErrInvalidMessage
	}

	n = msg.PackedSize() + HeaderSize
	header := Header{uint16(n), msg.Type()}
	header.Pack(buf)
	n2, err := msg.Pack(buf[HeaderSize:])
	if err != nil {
		return -1, err
	}
	if n2+HeaderSize != n {
		return -1, ErrInvalidMessage
	}

	return n, nil
}

// parseMessage allocates the respective message type and parses the given body data into it.
func parseMessage(msgType Type, body []byte) (Message, error) {
	switch msgType {
	case TypeOnionTunnelBuild:
		msg := new(OnionTunnelBuild)
		err := msg.Parse(body)
		return msg, err

	case TypeOnionTunnelReady:
		msg := new(OnionTunnelReady)
		err := msg.Parse(body)
		return msg, err

	case TypeOnionTunnelIncoming:
		msg := new(OnionTunnelIncoming)
		err := msg.Parse(body)
		return msg, err

	case TypeOnionTunnelDestroy:
		msg := new(OnionTunnelDestroy)
		err := msg.Parse(body)
		return msg, err

	case TypeOnionTunnelData:
		msg := new(OnionTunnelData)
		err := msg.Parse(body)
		return msg, err

	case TypeOnionError:
		msg := new(OnionError)
		err := msg.Parse(body)
		return msg, err

	case TypeOnionCover:
		msg := new(OnionCover)
		err := msg.Parse(body)
		return msg, err

	default:
		return nil, ErrInvalidMessage
	}
}

func ReadIP(ipv6 bool, data []byte) net.IP {
	if ipv6 {
		return net.IP{
			data[15], data[14], data[13], data[12],
			data[11], data[10], data[9], data[8],
			data[7], data[6], data[5], data[4],
			data[3], data[2], data[1], data[0]}
	}

	return net.IP{data[3], data[2], data[1], data[0]}
}

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
