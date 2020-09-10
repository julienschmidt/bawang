package p2p

// TunnelCreate commands a peer to create a tunnel to a given peer.
type TunnelCreate struct {
	Version  uint8
	Reserved uint16

	// encrypted next hop Diffie-Hellman pub key used to derive the shared Diffie-Hellman session key
	// encrypted with the next hops identifier public key for implicit authentication
	EncDHPubKey [512]byte
}

func (msg *TunnelCreate) Type() Type {
	return TypeTunnelCreate
}

func (msg *TunnelCreate) Parse(data []byte) (err error) {
	const size = 1 + 2 + len(msg.EncDHPubKey)
	if len(data) < size {
		return ErrInvalidMessage
	}

	msg.Version = data[0]

	// 1 byte reserved

	copy(msg.EncDHPubKey[:], data[3:3+len(msg.EncDHPubKey)])

	return nil
}

func (msg *TunnelCreate) PackedSize() (n int) {
	return 1 + 2 + len(msg.EncDHPubKey)
}

func (msg *TunnelCreate) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	buf = buf[0:n]

	buf[0] = msg.Version
	buf[1] = 0x00 // reserved
	buf[2] = 0x00 // reserved

	copy(buf[3:3+len(msg.EncDHPubKey)], msg.EncDHPubKey[:])

	return n, nil
}

type TunnelCreated struct {
	DHPubKey      [32]byte
	SharedKeyHash [32]byte
}

func (msg *TunnelCreated) Type() Type {
	return TypeTunnelCreated
}

func (msg *TunnelCreated) Parse(data []byte) (err error) {
	const size = 3 + 32 + 32
	if len(data) < size {
		return ErrInvalidMessage
	}

	copy(msg.DHPubKey[0:32], data[3:35])
	copy(msg.SharedKeyHash[0:32], data[35:67])

	return
}

func (msg *TunnelCreated) PackedSize() (n int) {
	return 3 + 32 + 32
}

func (msg *TunnelCreated) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	buf = buf[0:n]

	copy(buf[3:35], msg.DHPubKey[0:32])
	copy(buf[35:67], msg.SharedKeyHash[0:32])

	return n, nil
}

type TunnelDestroy struct {
	// TODO: somehow auth?
}

func (msg *TunnelDestroy) Type() Type {
	return TypeTunnelDestroy
}

func (msg *TunnelDestroy) Parse(data []byte) (err error) {
	const size = 3 // padding
	if len(data) < size {
		return ErrInvalidMessage
	}

	return
}

func (msg *TunnelDestroy) PackedSize() (n int) {
	return 3
}

func (msg *TunnelDestroy) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	copy(buf[0:3], []byte{0x00, 0x00, 0x00}) // padding

	return n, nil
}

type TunnelRelay struct {
	EncData [MaxRelayDataSize]byte
}

func (msg *TunnelRelay) Type() Type {
	return TypeTunnelRelay
}

func (msg *TunnelRelay) Parse(data []byte) (err error) {
	const minSize = RelayHeaderSize
	if len(data) < minSize || len(data) > MaxRelayDataSize {
		return ErrInvalidMessage
	}

	copy(msg.EncData[:len(data)], data)
	return
}

func (msg *TunnelRelay) PackedSize() (n int) {
	return RelayHeaderSize + len(msg.EncData)
}

func (msg *TunnelRelay) Pack(buf []byte) (n int, err error) {
	n = msg.PackedSize()
	if cap(buf) < n {
		return -1, ErrBufferTooSmall
	}
	copy(buf[:n], msg.EncData[:])

	return n, nil
}
