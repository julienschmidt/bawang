package onion

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	mathRand "math/rand"
	"net"
	"time"

	"golang.org/x/crypto/nacl/box"

	"bawang/api"
	"bawang/p2p"
)

var (
	ErrInvalidProtocolVersion = errors.New("invalid protocol version")
	ErrInvalidDHPublicKey     = errors.New("invalid DH public key")
	ErrNotEnoughHops          = errors.New("tunnel does contain fewer than 3 hops")
	ErrMisbehavingPeer        = errors.New("a peer is sending invalid messages or violating protocol")
)

type Peer struct {
	DHShared [32]byte
	Port     uint16
	Address  net.IP
	HostKey  *rsa.PublicKey
}

type Tunnel struct {
	ID      uint32
	Hops    []*Peer
	Link    *Link
	Counter uint64
}

func (tunnel *Tunnel) EncryptRelayMsg(relayMsg []byte) (encryptedMsg []byte, err error) {
	encryptedMsg = relayMsg
	for _, hop := range tunnel.Hops {
		encryptedMsg, err = p2p.EncryptRelay(encryptedMsg, &hop.DHShared)
		if err != nil { // error when decrypting
			return
		}
	}
	return
}

func (tunnel *Tunnel) DecryptRelayMessage(data []byte) (relayHdr p2p.RelayHeader, decryptedRelayMsg []byte, ok bool, err error) {
	decryptedRelayMsg = data
	for _, hop := range tunnel.Hops {
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

type TunnelSegment struct {
	PrevHopTunnelID uint32
	NextHopTunnelID uint32
	PrevHopLink     *Link
	NextHopLink     *Link     // can be nil if the tunnel terminates at the current hop
	DHShared        *[32]byte // Diffie-Hellman key shared with the previous hop
}

func generateDHKeys(peerHostKey *rsa.PublicKey) (privDH, encDHPubKey *[32]byte, err error) {
	pubDH, privDH, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	encDHKey, err := rsa.EncryptPKCS1v15(rand.Reader, peerHostKey, pubDH[:])
	if err != nil {
		return nil, nil, err
	}

	if len(encDHKey) != 32 {
		return nil, nil, ErrInvalidDHPublicKey
	}
	encDHPubKey = new([32]byte)
	copy(encDHPubKey[:], encDHKey[:32])

	return privDH, encDHPubKey, nil
}

func CreateTunnelCreate(peerHostKey *rsa.PublicKey) (privDH *[32]byte, msg *p2p.TunnelCreate, err error) {
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

func CreateTunnelExtend(peerHostKey *rsa.PublicKey, address net.IP, port uint16) (privDH *[32]byte, msg *p2p.RelayTunnelExtend, err error) {
	privDH, encDHPubKey, err := generateDHKeys(peerHostKey)
	if err != nil {
		return nil, nil, err
	}

	msg = &p2p.RelayTunnelExtend{
		IPv6:        address.To16() != nil, // TODO: figure out if this is hacky or intended
		Address:     address,
		Port:        port,
		EncDHPubKey: *encDHPubKey,
	}

	return privDH, msg, nil
}

func HandleTunnelCreate(msg p2p.TunnelCreate, cfg *Config) (dhShared *[32]byte, response *p2p.TunnelCreated, err error) {
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

type Onion struct {
	Links []*Link
	// maps which api connections listen on which tunnels in addition to keeping track of existing tunnels
	Tunnels map[uint32][]*api.Connection

	OutgoingTunnels map[uint32]*Tunnel
	IncomingTunnels map[uint32]*TunnelSegment

	APIConnections []*api.Connection
}

// here are the functions used by the module communicating with the API
func (onion *Onion) BuildTunnel(cfg *Config, hops []*Peer) (tunnel *Tunnel, err error) {
	if len(hops) < 3 {
		return nil, ErrNotEnoughHops
	}

	msgBuf := make([]byte, p2p.MaxSize)

	// generate a new, unique tunnel ID
	tunnelID := onion.NewTunnelID()

	// first we fetch us a link connection to the first hop
	link, err := onion.GetOrCreateLink(hops[0].Address, hops[0].Port)
	if err != nil {
		return nil, err
	}

	tunnel = &Tunnel{
		Link: link,
		ID:   tunnelID,
	}

	// now we register a output channel for this link
	dataOut := make(chan message, 5) // TODO: determine queue size
	err = link.register(tunnelID, dataOut)
	if err != nil {
		return nil, err
	}

	// send a create message to the first hop
	dhPriv, createMsg, err := CreateTunnelCreate(hops[0].HostKey)
	if err != nil {
		return nil, err
	}

	err = link.Send(tunnelID, createMsg)
	if err != nil {
		return nil, err
	}

	// now we wait for the response, timeouting when one does not come
	select {
	case created := <-dataOut:
		if created.hdr.Type != p2p.TypeTunnelCreated {
			return nil, p2p.ErrInvalidMessage
		}

		createdMsg := p2p.TunnelCreated{}
		err = createdMsg.Parse(created.payload)
		if err != nil {
			return nil, err
		}

		var dhShared [32]byte
		box.Precompute(&dhShared, &createdMsg.DHPubKey, dhPriv)

		// validate the shared key hash
		sharedHash := sha256.Sum256(dhShared[:32])
		if !bytes.Equal(sharedHash[:], createdMsg.SharedKeyHash[:]) {
			return nil, ErrMisbehavingPeer
		}

		tunnel.Hops = []*Peer{{
			DHShared: dhShared,
			Port:     hops[0].Port,
			Address:  hops[0].Address,
			HostKey:  hops[0].HostKey,
		}}

		break

	case <-time.After(time.Duration(cfg.CreateTimeout) * time.Second):
		return nil, ErrTimedOut
	}

	// handshake with first hop is done, do the remaining ones
	for _, hop := range hops[1:] {
		dhPriv, extendMsg, err := CreateTunnelExtend(hop.HostKey, hop.Address, hop.Port)
		if err != nil {
			return nil, err
		}

		n, err := p2p.PackRelayMessage(msgBuf, tunnel.Counter, extendMsg)
		if err != nil {
			return nil, err
		}

		// layer on encryption
		packedMsg := msgBuf[:n]
		for j := len(tunnel.Hops) - 1; j > 1; j-- {
			var encMsg []byte
			encMsg, err = p2p.EncryptRelay(packedMsg, &tunnel.Hops[j].DHShared)
			if err != nil {
				return nil, err
			}
			packedMsg = encMsg
		}

		err = link.SendRaw(tunnelID, p2p.TypeTunnelRelay, packedMsg)
		if err != nil {
			return nil, err
		}

		// wait for the extended message
		select {
		case extended := <-dataOut:
			if extended.hdr.Type != p2p.TypeTunnelRelay {
				err = p2p.ErrInvalidMessage
				return nil, err
			}

			// decrypt the message
			relayHdr, decryptedRelayMsg, ok, err := tunnel.DecryptRelayMessage(extended.payload)
			if err != nil {
				return nil, err
			}
			if !ok || relayHdr.RelayType != p2p.RelayTypeTunnelExtended {
				err = ErrMisbehavingPeer
				return nil, err
			}

			extendedMsg := p2p.RelayTunnelExtended{}
			err = extendedMsg.Parse(decryptedRelayMsg)
			if err != nil {
				return nil, err
			}

			var dhShared [32]byte
			box.Precompute(&dhShared, &extendedMsg.DHPubKey, dhPriv)

			// validate the shared key hash
			sharedHash := sha256.Sum256(dhShared[:32])
			if !bytes.Equal(sharedHash[:], extendedMsg.SharedKeyHash[:]) {
				return nil, ErrMisbehavingPeer
			}

			tunnel.Hops = append(tunnel.Hops, &Peer{
				DHShared: dhShared,
				Port:     hops[0].Port,
				Address:  hops[0].Address,
				HostKey:  hops[0].HostKey,
			})

			break
		case <-time.After(time.Duration(cfg.CreateTimeout) * time.Second):
			return nil, ErrTimedOut
		}
	}

	return tunnel, nil
}

func (onion *Onion) SendData(tunnelID uint32, payload []byte) (err error) {
	if tunnel, ok := onion.OutgoingTunnels[tunnelID]; ok {
		var encryptedMsg []byte
		encryptedMsg, err = tunnel.EncryptRelayMsg(payload)
		if err != nil {
			return err
		}

		return tunnel.Link.SendRaw(tunnelID, p2p.TypeTunnelRelay, encryptedMsg)
	} else if tunnelSegment, ok := onion.IncomingTunnels[tunnelID]; ok {
		var encryptedMsg []byte
		encryptedMsg, err = p2p.EncryptRelay(payload, tunnelSegment.DHShared)
		if err != nil {
			return err
		}

		return tunnelSegment.PrevHopLink.SendRaw(tunnelID, p2p.TypeTunnelRelay, encryptedMsg)
	}

	return ErrInvalidTunnel
}

// more internal functions
func (onion *Onion) SendMsgToAllAPI(msg api.Message) (err error) {
	for _, apiConn := range onion.APIConnections {
		sendError := apiConn.Send(msg)
		if sendError != nil {
			sendError = apiConn.Terminate()
			onion.RemoveAPIConnection(apiConn)
		}
	}

	return nil
}

func (onion *Onion) SendMsgToAPI(tunnelID uint32, msg api.Message) (err error) {
	apiConns, ok := onion.Tunnels[tunnelID]
	if !ok {
		return ErrInvalidTunnel
	}
	for _, apiConn := range apiConns {
		sendError := apiConn.Send(msg)
		if sendError != nil {
			sendError = apiConn.Terminate()
			onion.RemoveAPIConnection(apiConn)
		}
	}

	return nil
}

func (onion *Onion) RegisterIncomingConnection(tunnelID uint32) (err error) {
	if _, ok := onion.Tunnels[tunnelID]; !ok {
		return ErrInvalidTunnel
	}

	onion.Tunnels[tunnelID] = make([]*api.Connection, len(onion.APIConnections))
	copy(onion.Tunnels[tunnelID], onion.APIConnections)

	incomingMsg := api.OnionTunnelIncoming{
		TunnelID: tunnelID,
	}

	return onion.SendMsgToAllAPI(&incomingMsg)
}

func (onion *Onion) RemoveAPIConnection(apiConn *api.Connection) {
	for tunnelID := range onion.Tunnels {
		onion.RemoveAPIConnectionFromTunnel(tunnelID, apiConn)
	}

	for i, conn := range onion.APIConnections {
		if conn == apiConn {
			onion.APIConnections = append(onion.APIConnections[:i], onion.APIConnections[i+1:]...)
			break
		}
	}
}

func (onion *Onion) RemoveAPIConnectionFromTunnel(tunnelID uint32, apiConn *api.Connection) {
	if _, ok := onion.Tunnels[tunnelID]; !ok {
		return
	}

	for i, conn := range onion.Tunnels[tunnelID] {
		if conn == apiConn {
			onion.Tunnels[tunnelID] = append(onion.Tunnels[tunnelID][:i], onion.Tunnels[tunnelID][i+1:]...)
			break
		}
	}
}

func (onion *Onion) NewTunnelID() (tunnelID uint32) {
	random := mathRand.New(mathRand.NewSource(time.Now().UnixNano())) //nolint:gosec // pseudo-rand is good enough. We just need uniqueness.
	tunnelID = random.Uint32()
	// ensure that tunnelID is unique
	for {
		if _, ok := onion.Tunnels[tunnelID]; ok {
			tunnelID = random.Uint32() // non unique tunnel ID
			continue
		}
		break
	}

	onion.Tunnels[tunnelID] = make([]*api.Connection, 0)

	return tunnelID
}

func (onion *Onion) RemoveTunnel(tunnelID uint32) {
	if _, ok := onion.Tunnels[tunnelID]; !ok {
		return
	}

	// TODO: determine if we can even send an error message to the api in a way to let them know the tunnel is gone
	// onionErrMsg := api.OnionError{
	// 	TunnelID: tunnelID,
	// 	RequestType: api.TypeOnionTunnelReady,
	// }
	// err = onion.SendMsgToAPI(tunnelID, &onionErrMsg)

	for _, link := range onion.Links {
		if link.HasTunnel(tunnelID) {
			link.RemoveTunnel(tunnelID)
		}
	}

	delete(onion.Tunnels, tunnelID)
}

func (onion *Onion) GetLink(address net.IP, port uint16) (*Link, bool) {
	for _, link := range onion.Links {
		if link.Address.Equal(address) && link.Port == port {
			return link, true
		}
	}
	return nil, false
}

func (onion *Onion) GetOrCreateLink(address net.IP, port uint16) (link *Link, err error) {
	link, ok := onion.GetLink(address, port)
	if ok {
		return
	}

	link, err = NewLink(address, port)
	if err != nil {
		return nil, err
	}

	onion.Links = append(onion.Links, link)
	return link, nil
}
