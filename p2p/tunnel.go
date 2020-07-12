package p2p

import (
	"net"
)

// TunnelCreate commands a peer to create a tunnel to a given peer.
type TunnelCreate struct {
	Version     uint8
	Reserved    uint8
	EncDHPubKey [32]byte // next hop pub key encrypted with current tunnel end pub key
}

type TunnelCreated struct {
	DHPubKey      [32]byte
	SharedKeyHash [32]byte
}

// TunnelExtend commands the current tunnel end to extend it by another hop.
type TunnelExtend struct {
	// TODO: encrypted DH key -> next hop creates TunnelCreate message from it
	EncDHPubKey [32]byte // encrypted with peer pub key
	// TODO: pub key of next peer
	DHPubKey [32]byte
	// TODO: end point: addr (ip:port)
	Port    uint16
	Address net.IP
}

type TunnelExtended struct {
	EncDHPubKey [32]byte // encrypted pub key of next peer
	// TODO: encrypted MAC
}

type RelayHeader struct {
	RelayType uint16
	// TODO: Digest
	Length uint16
}

// TODO: wraps a data packet
type TunnelRelay struct {
	EncData []byte
}

// TunnelData is encrypted data
// TODO: wrapped in a relay packet between hops
type TunnelData struct {
	Data []byte
}

type TunnelDestroy struct {
	// TODO: somehow auth?
}
