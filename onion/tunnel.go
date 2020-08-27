package onion

import (
	"bawang/p2p"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"golang.org/x/crypto/nacl/box"
	"net"
)

var (
	ErrInvalidProtocolVersion = errors.New("invalid protocol version")
	ErrInvalidDHPublicKey     = errors.New("invalid DH public key")
)

type Peer struct {
	DHShared *[32]byte
	Port     uint16
	Address  net.IP
	HostKey  *rsa.PublicKey
}

type Tunnel struct {
	ID   uint32
	Hops []*Peer
}

type TunnelSegment struct {
	PrevHopTunnelID uint32
	NextHopTunnelID uint32
	NextHopLink     *Link     // can be nil if the tunnel terminates at the current hop
	DHShared        *[32]byte // diffie hellman key shared with the previous hop
}

func HandleTunnelCreate(msg p2p.TunnelCreate, cfg *Config) (dhShared *[32]byte, response p2p.TunnelCreated, err error) {
	if msg.Version == 1 {
		// decrypt the received dh pub key
		label := []byte("dhshared")
		decDHKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, cfg.HostKey, msg.EncDHPubKey[:], label)
		if err != nil {
			return nil, response, err
		}

		if len(decDHKey) != 32 {
			err = ErrInvalidDHPublicKey
			return nil, response, err
		}

		peerDHPub := new([32]byte)
		copy(peerDHPub[:], decDHKey[:32])

		pubDH, privDH, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, response, err
		}
		dhShared = new([32]byte)
		box.Precompute(dhShared, peerDHPub, privDH)

		response = p2p.TunnelCreated{
			DHPubKey:      *pubDH,
			SharedKeyHash: sha256.Sum256(dhShared[:32]),
		}
		return dhShared, response, err

	} else {
		err = ErrInvalidProtocolVersion
		return
	}
}

func CreateMsgFromExtendMsg(msg p2p.RelayTunnelExtend) (createMsg p2p.TunnelCreate) {
	createMsg.EncDHPubKey = msg.EncDHPubKey
	createMsg.Version = 1 // implement other versions of the handshake protocol here

	return
}

func ExtendedMsgFromCreatedMsg(msg p2p.TunnelCreated) (extendedMsg p2p.RelayTunnelExtended) {
	extendedMsg.DHPubKey = msg.DHPubKey
	extendedMsg.SharedKeyHash = msg.SharedKeyHash

	return
}
