package p2p

type Type uint16

const (
	TypeTunnelCreate   Type = 101
	TypeTunnelCreated  Type = 102
	TypeTunnelExtend   Type = 103
	TypeTunnelExtended Type = 104
	TypeTunnelRelay    Type = 105
	TypeTunnelData     Type = 106
	TypeTunnelDestroy  Type = 107
	// Tunnel reserved until 199
)
