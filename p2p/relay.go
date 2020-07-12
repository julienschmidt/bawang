package p2p

import (
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
	digestOffset := 2

	hdr.RelayType = RelayType(binary.BigEndian.Uint16(data))
	copy(hdr.Digest[:], data[digestOffset:digestOffset+8])
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
	EncDHPubKey [32]byte // encrypted with peer pub key
	IPv6        bool
	Port        uint16
	Address     net.IP
}

type RelayTunnelExtended struct {
	EncDHPubKey      [32]byte // encrypted pub key of next peer
	EncSharedKeyHash [32]byte
}

// RelayTunnelData is encrypted data
// TODO: wrapped in a relay packet between hops
type RelayTunnelData struct {
	Data []byte
}
