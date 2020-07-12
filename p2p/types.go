package p2p

type Type uint16
type RelayType uint16

const (
	TypeTunnelCreate   Type = 51
	TypeTunnelCreated  Type = 52
	TypeTunnelDestroy  Type = 53
	TypeTunnelRelay    Type = 54
	// Tunnel reserved until 100

	// Relay sub protocol
	RelayTypeTunnelExtend   RelayType = 101
	RelayTypeTunnelExtended RelayType = 102
	RelayTypeTunnelData     RelayType = 103
	// Relay sub protocol reserved until 150
)
