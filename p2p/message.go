package p2p

import (
	"encoding/binary"
	"errors"
)

const (
	HeaderSize = 4 + 2
)

var (
	ErrInvalidMessage = errors.New("invalid message")
)

type Header struct {
	TunnelID uint32
	Type     Type
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

func (hdr *Header) Pack(buf []byte) {
	binary.BigEndian.PutUint32(buf, hdr.TunnelID)
	binary.BigEndian.PutUint16(buf[4:], uint16(hdr.Type))
}
