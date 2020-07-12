package p2p

import (
	//"encoding/binary"
	"net"
)

const (
	RelayHeaderSize = 2 + 8
)

// RelayHeader is the header of a relay sub protocol protocol cell
type RelayHeader struct {
	RelayType uint16
	Digest    [8]byte // TODO: determine digest length
}

// RelayTunnelExtend commands the addressed tunnel hop to extend the tunnel by another hop.
type RelayTunnelExtend struct {
	// TODO: encrypted DH key -> next hop creates TunnelCreate message from it
	EncDHPubKey [32]byte // encrypted with peer pub key
	// TODO: end point: addr (ip:port)
	IPv6    bool
	Port    uint16
	Address net.IP
	// TODO: pub key of next peer
	DestHostKey []byte
}

type RelayTunnelExtended struct {
	EncDHPubKey      [32]byte // encrypted pub key of next peer
	EncSharedKeyHash [32]byte // TODO: determine length
}

// RelayTunnelData is encrypted data
// TODO: wrapped in a relay packet between hops
type RelayTunnelData struct {
	Data []byte
}
