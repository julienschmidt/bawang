// Package p2p provides types and helper functions to send and receive P2P messages.
package p2p

type Type uint8

const (
	TypeTunnelCreate  Type = 1
	TypeTunnelCreated Type = 2
	TypeTunnelDestroy Type = 3
	TypeTunnelRelay   Type = 4
	// Tunnel reserved until 20
)

// Relay sub protocol
type RelayType uint8

const (
	RelayTypeTunnelExtend   RelayType = 1
	RelayTypeTunnelExtended RelayType = 2
	RelayTypeTunnelData     RelayType = 3
	RelayTypeTunnelCover    RelayType = 4
	// Tunnel reserved until 10
)
