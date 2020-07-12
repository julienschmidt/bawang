package p2p

import "net"

// TunnelCreate commands a peer to create a tunnel to a given peer.
type TunnelCreate struct {
	DHPubKey [32]byte // next hop diffie hellman pub key used to derive the shared diffie hellman session key
}

type TunnelCreated struct {
	DHPubKey      [32]byte
	SharedKeyHash [32]byte // TODO: do we need 32 bytes hash?
}

type TunnelDestroy struct {
	// TODO: somehow auth?
}

// RelayHeader represents the header in a relay sub protocol protocol cell
type RelayHeader struct {
	RelayType uint16
	// TODO: determine digest length
	Digest [8]byte
	Length uint16
}

// TunnelExtend commands the addressed tunnel hop to extend the tunnel by another hop.
type TunnelExtend struct {
	// TODO: encrypted DH key -> next hop creates TunnelCreate message from it
	EncDHPubKey [32]byte // encrypted with peer pub key
	// TODO: end point: addr (ip:port)
	IPv6    bool
	Port    uint16
	Address net.IP
	// TODO: pub key of next peer
	DestHostKey []byte
}

type TunnelExtended struct {
	EncDHPubKey      [32]byte // encrypted pub key of next peer
	EncSharedKeyHash [32]byte // TODO: determine length
}

// TunnelData is encrypted data
// TODO: wrapped in a relay packet between hops
type TunnelData struct {
	Data []byte
}
