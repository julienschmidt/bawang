package p2p

// TunnelCreate commands a peer to create a tunnel to a given peer.
type TunnelCreate struct {
	Version  uint8
	Reserved uint8
	DHPubKey [32]byte // next hop Diffie-Hellman pub key used to derive the shared Diffie-Hellman session key
}

func (msg *TunnelCreate) Type() Type {
	return TypeTunnelCreate
}

func (msg *TunnelCreate) Parse(data []byte) (err error) {
	const size = 1 + 1 + 32
	if len(data) != size {
		return ErrInvalidMessage
	}

	msg.Version = data[0]

	// 1 byte reserved

	copy(msg.DHPubKey[0:32], data[2:34])

	return
}

func (msg *TunnelCreate) PackedSize() (n int) {
	return 1 + 1 + 32
}

func (msg *TunnelCreate) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	buf = buf[0:n]

	buf[0] = msg.Version
	buf[1] = 0x00 // reserved

	copy(buf[2:34], msg.DHPubKey[0:32])

	return n, nil
}

type TunnelCreated struct {
	DHPubKey   [32]byte // diffie hellman public key encrypted with the next hop identifier public key
	SharedKeyHash [32]byte // TODO: do we need 32 bytes hash?
}

func (msg *TunnelCreated) Type() Type {
	return TypeTunnelCreated
}

func (msg *TunnelCreated) Parse(data []byte) (err error) {
	const size = 32 + 32
	if len(data) != size {
		return ErrInvalidMessage
	}

	copy(msg.DHPubKey[0:32], data[0:32])
	copy(msg.SharedKeyHash[0:32], data[32:64])

	return
}

func (msg *TunnelCreated) PackedSize() (n int) {
	return 32 + 32
}

func (msg *TunnelCreated) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	buf = buf[0:n]

	copy(buf[0:32], msg.DHPubKey[0:32])
	copy(buf[32:64], msg.SharedKeyHash[0:32])

	return n, nil
}

type TunnelDestroy struct {
	// TODO: somehow auth?
}

func (msg *TunnelDestroy) Type() Type {
	return TypeTunnelDestroy
}

func (msg *TunnelDestroy) Parse(data []byte) (err error) {
	const size = 0
	if len(data) != size {
		return ErrInvalidMessage
	}

	return
}

func (msg *TunnelDestroy) PackedSize() (n int) {
	return 0
}

func (msg *TunnelDestroy) Pack(buf []byte) (n int, err error) {
	return n, nil
}

type TunnelRelay struct {
	RelayHeader
	Data []byte
}

func (msg *TunnelRelay) Type() Type {
	return TypeTunnelRelay
}

func (msg *TunnelRelay) Parse(data []byte) (err error) {
	const minSize = RelayHeaderSize
	if len(data) != minSize {
		return ErrInvalidMessage
	}

	// TODO: actual parsing

	return
}

func (msg *TunnelRelay) PackedSize() (n int) {
	return RelayHeaderSize + len(msg.Data)
}

func (msg *TunnelRelay) Pack(buf []byte) (n int, err error) {
	// TODO: actual packing

	n = msg.PackedSize()

	return n, nil
}
