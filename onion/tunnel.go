package onion

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"net"

	"golang.org/x/crypto/nacl/box"

	"bawang/config"
	"bawang/p2p"
	"bawang/rps"
)

var (
	ErrInvalidProtocolVersion = errors.New("invalid protocol version")
	ErrInvalidDHPublicKey     = errors.New("invalid DH public key")
	ErrNotEnoughHops          = errors.New("tunnel does contain fewer than 3 hops")
	ErrMisbehavingPeer        = errors.New("a peer is sending invalid messages or violating protocol")
)

// Tunnel keeps track of the state of an onion tunnel initiated by the current peer.
type Tunnel struct {
	id          uint32
	sendCounter uint32
	recvCounter uint32
	hops        []*rps.Peer
	link        *Link
	quit        chan struct{}
}

// ID returns the tunnel's ID
func (tunnel *Tunnel) ID() uint32 {
	return tunnel.id
}

// Close terminates the outgoing tunnel, sending p2p.TypeTunnelDestroy through the tunnel.
func (tunnel *Tunnel) Close() (err error) {
	close(tunnel.quit)
	err = tunnel.link.sendDestroyTunnel(tunnel.ID())
	return err
}

// EncryptRelayMsg encrypts a packed relay message with the intermediate hops keys.
func (tunnel *Tunnel) EncryptRelayMsg(relayMsg []byte) (encryptedMsg []byte, err error) {
	encryptedMsg = relayMsg
	for _, hop := range tunnel.hops {
		encryptedMsg, err = p2p.EncryptRelay(encryptedMsg, &hop.DHShared)
		if err != nil { // error when decrypting
			return
		}
	}
	return
}

// DecryptRelayMessage removes the layered encryption from a received relay message.
// If the checksum does not match will return ok=false.
func (tunnel *Tunnel) DecryptRelayMessage(data []byte) (relayHdr p2p.RelayHeader, decryptedRelayMsg []byte, ok bool, err error) {
	decryptedRelayMsg = data
	for _, hop := range tunnel.hops {
		ok, decryptedRelayMsg, err = p2p.DecryptRelay(decryptedRelayMsg, &hop.DHShared)
		if err != nil { // error when decrypting
			return
		}

		if ok { // message is meant for us from a hop
			relayHdr = p2p.RelayHeader{}
			err = relayHdr.Parse(decryptedRelayMsg)
			if err != nil {
				return
			}

			decryptedRelayMsg = decryptedRelayMsg[p2p.RelayHeaderSize:relayHdr.Size]
			return
		}
	}

	// we could not decrypt the message and have removed all layers of encryption
	return relayHdr, nil, false, p2p.ErrInvalidMessage
}

// tunnelSegment is used to keep track of an incoming tunnels state.
type tunnelSegment struct {
	prevHopTunnelID uint32
	nextHopTunnelID uint32
	prevHopLink     *Link
	nextHopLink     *Link     // can be nil if the tunnel terminates at the current hop
	dhShared        *[32]byte // Diffie-Hellman key shared with the previous hop
	sendCounter     uint32
	recvCounter     uint32

	quit chan struct{}
}

// Close terminates a tunnelSegment by sending p2p.TypeTunnelDestroy messages to the previous and next hop.
func (tunnel *tunnelSegment) Close() (err error) {
	close(tunnel.quit)
	err = tunnel.prevHopLink.sendDestroyTunnel(tunnel.prevHopTunnelID)
	if err != nil && tunnel.nextHopLink != nil {
		_ = tunnel.prevHopLink.sendDestroyTunnel(tunnel.prevHopTunnelID)
	} else if tunnel.nextHopLink != nil {
		err = tunnel.prevHopLink.sendDestroyTunnel(tunnel.prevHopTunnelID)
	}

	return err
}

// handleTunnelCreate returns the shared Diffie-Hellman key and a p2p.TunnelCreated response for an incoming p2p.TunnelCreate command.
func handleTunnelCreate(msg *p2p.TunnelCreate, cfg *config.Config) (dhShared *[32]byte, response *p2p.TunnelCreated, err error) {
	if msg.Version != 1 {
		return nil, nil, ErrInvalidProtocolVersion
	}

	// decrypt the received dh pub key
	decDHKey, err := rsa.DecryptPKCS1v15(rand.Reader, cfg.HostKey, msg.EncDHPubKey[:])
	if err != nil {
		return nil, nil, err
	}

	if len(decDHKey) != 32 {
		return nil, nil, ErrInvalidDHPublicKey
	}

	peerDHPub := new([32]byte)
	copy(peerDHPub[:], decDHKey[:32])

	pubDH, privDH, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	dhShared = new([32]byte)
	box.Precompute(dhShared, peerDHPub, privDH)

	response = &p2p.TunnelCreated{
		DHPubKey:      *pubDH,
		SharedKeyHash: sha256.Sum256(dhShared[:32]),
	}
	return dhShared, response, nil
}

// generateDHKeys generates new Diffie-Hellman keys, encrypting the public part with the given peers host identifier key.
func generateDHKeys(peerHostKey *rsa.PublicKey) (privDH *[32]byte, encDHPubKey *[512]byte, err error) {
	pubDH, privDH, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	encDHKey, err := rsa.EncryptPKCS1v15(rand.Reader, peerHostKey, pubDH[:])
	if err != nil {
		return nil, nil, err
	}

	if len(encDHKey) != 512 {
		return nil, nil, ErrInvalidDHPublicKey
	}
	encDHPubKey = new([512]byte)
	copy(encDHPubKey[:], encDHKey[:512])

	return privDH, encDHPubKey, nil
}

// tunnelCreateMsg generates new Diffie-Hellman keys and a p2p.TunnelCreate to initiate a new onion connection
// to a new peer.
func tunnelCreateMsg(peerHostKey *rsa.PublicKey) (privDH *[32]byte, msg *p2p.TunnelCreate, err error) {
	privDH, encDHPubKey, err := generateDHKeys(peerHostKey)
	if err != nil {
		return nil, nil, err
	}

	msg = &p2p.TunnelCreate{
		Version:     1,
		EncDHPubKey: *encDHPubKey,
	}
	return privDH, msg, nil
}

// relayTunnelExtendMsg generates new Diffie-Hellman keys and a p2p.RelayTunnelExtend to extend an existing onion tunnel
// to the given peer.
func relayTunnelExtendMsg(peerHostKey *rsa.PublicKey, address net.IP, port uint16) (privDH *[32]byte, msg *p2p.RelayTunnelExtend, err error) {
	privDH, encDHPubKey, err := generateDHKeys(peerHostKey)
	if err != nil {
		return nil, nil, err
	}

	msg = &p2p.RelayTunnelExtend{
		IPv6:        address.To16() != nil,
		Address:     address,
		Port:        port,
		EncDHPubKey: *encDHPubKey,
	}
	return privDH, msg, nil
}

// tunnelCreateMsgFromRelayTunnelExtendMsg creates a p2p.TunnelCreate from the given p2p.RelayTunnelExtend
func tunnelCreateMsgFromRelayTunnelExtendMsg(msg *p2p.RelayTunnelExtend) (createMsg p2p.TunnelCreate) {
	createMsg.EncDHPubKey = msg.EncDHPubKey
	createMsg.Version = 1 // implement other versions of the handshake protocol here
	return
}

// relayTunnelExtendedMsgFromTunnelCreatedMsg returns a p2p.RelayTunnelExtended from the given p2p.TunnelCreated
func relayTunnelExtendedMsgFromTunnelCreatedMsg(msg *p2p.TunnelCreated) (extendedMsg p2p.RelayTunnelExtended) {
	extendedMsg.DHPubKey = msg.DHPubKey
	extendedMsg.SharedKeyHash = msg.SharedKeyHash
	return
}
