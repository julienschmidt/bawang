// Package onion provides the onion routing logic.
package onion

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	mathRand "math/rand"
	"net"
	"time"

	"golang.org/x/crypto/nacl/box"

	"bawang/api"
	"bawang/config"
	"bawang/p2p"
	"bawang/rps"
)

// Router is the central onion routing logic state tracking struct.
// It tracks existing Link references, connected API clients with respective api.Connection objects
// and all currently open outgoing and incoming tunnels.
type Router struct {
	cfg *config.Config
	rps rps.RPS

	links []*Link

	// maps which API connections listen on which tunnels in addition to keeping track of existing tunnels
	tunnels map[uint32][]*api.Connection

	outgoingTunnels map[uint32]*Tunnel
	incomingTunnels map[uint32]*tunnelSegment

	// keeps track of known API connections, which will then receive future api.OnionTunnelIncoming solicitations
	// and can instruct the onion module to build new tunnels
	apiConnections []*api.Connection
}

// NewRouter creates a new Router using the given config.Config.
func NewRouter(cfg *config.Config) (*Router, error) {
	rps, err := rps.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("error initializing RPS: %w", err)
	}

	return newRouterWithRPS(cfg, rps), nil
}

func newRouterWithRPS(cfg *config.Config, rps rps.RPS) *Router {
	return &Router{
		cfg:             cfg,
		rps:             rps,
		tunnels:         make(map[uint32][]*api.Connection),
		outgoingTunnels: make(map[uint32]*Tunnel),
		incomingTunnels: make(map[uint32]*tunnelSegment),
		apiConnections:  []*api.Connection{},
	}
}

// RegisterAPIConnection adds an api.Connection to the onion router which will then receive future api.OnionTunnelIncoming
// solicitations and can instruct the onion module to build new tunnels.
func (r *Router) RegisterAPIConnection(apiConn *api.Connection) {
	r.apiConnections = append(r.apiConnections, apiConn)
}

// BuildTunnel takes care of fully initializing an onion tunnel through the given peers with the tunnels destination
// being the last peer in hops. The given api.Connection is registered with the created Tunnel and will receive
// onion traffic for this tunnel.
func (r *Router) BuildTunnel(targetPeer *rps.Peer, apiConn *api.Connection) (tunnel *Tunnel, err error) {
	if r.cfg.TunnelLength < 3 {
		return nil, ErrNotEnoughHops
	}

	// sample intermediate peers
	hops, err := r.rps.SampleIntermediatePeers(r.cfg.TunnelLength, targetPeer)
	if err != nil {
		return nil, fmt.Errorf("error sampling peers: %w", err)
	}

	msgBuf := make([]byte, p2p.MessageSize)

	// generate a new, unique tunnel ID
	tunnelID := r.newTunnelID()

	// first we fetch us a link connection to the first hop
	log.Printf("Starting to initialize onion circuit with first hop %v:%v\n", hops[0].Address, hops[0].Port)
	link, err := r.GetOrCreateLink(hops[0].Address, hops[0].Port)
	if err != nil {
		return nil, err
	}

	tunnel = &Tunnel{
		link: link,
		id:   tunnelID,
		quit: make(chan struct{}),
	}

	// now we register an output channel for this link
	dataOut := make(chan message, 5)
	err = link.register(tunnelID, dataOut)
	if err != nil {
		return nil, err
	}

	// send a create message to the first hop
	dhPriv, createMsg, err := tunnelCreateMsg(hops[0].HostKey)
	if err != nil {
		return nil, err
	}

	err = link.sendMsg(tunnelID, createMsg)
	if err != nil {
		return nil, err
	}

	// now we wait for the response, timing out when one does not come
	select {
	case created := <-dataOut:
		if created.hdr.Type != p2p.TypeTunnelCreated {
			return nil, p2p.ErrInvalidMessage
		}

		createdMsg := p2p.TunnelCreated{}
		err = createdMsg.Parse(created.body)
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

		tunnel.hops = []*rps.Peer{{
			DHShared: dhShared,
			Port:     hops[0].Port,
			Address:  hops[0].Address,
			HostKey:  hops[0].HostKey,
		}}

	case <-time.After(time.Duration(r.cfg.BuildTimeout) * time.Second):
		return nil, ErrTimedOut
	}

	// handshake with first hop is done, do the remaining ones
	for _, hop := range hops[1:] {
		dhPriv, extendMsg, err := relayTunnelExtendMsg(hop.HostKey, hop.Address, hop.Port)
		if err != nil {
			return nil, err
		}

		var n int
		tunnel.counter, n, err = p2p.PackRelayMessage(msgBuf, tunnel.counter, extendMsg)
		if err != nil {
			return nil, err
		}

		// layer on encryption
		packedMsg := msgBuf[:n]
		for j := len(tunnel.hops) - 1; j >= 0; j-- {
			packedMsg, err = p2p.EncryptRelay(packedMsg, &tunnel.hops[j].DHShared)
			if err != nil {
				return nil, err
			}
		}

		err = link.sendRelay(tunnelID, packedMsg)
		if err != nil {
			return nil, err
		}

		// wait for the extended message
		select {
		case extended := <-dataOut:
			if extended.hdr.Type != p2p.TypeTunnelRelay {
				return nil, p2p.ErrInvalidMessage
			}

			// decrypt the message
			relayHdr, decryptedRelayMsg, ok, err := tunnel.DecryptRelayMessage(extended.body)
			if err != nil {
				return nil, err
			}
			if !ok || relayHdr.RelayType != p2p.RelayTypeTunnelExtended {
				return nil, ErrMisbehavingPeer
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

			tunnel.hops = append(tunnel.hops, &rps.Peer{
				DHShared: dhShared,
				Port:     hops[0].Port,
				Address:  hops[0].Address,
				HostKey:  hops[0].HostKey,
			})

			break
		case <-time.After(time.Duration(r.cfg.BuildTimeout) * time.Second):
			return nil, ErrTimedOut
		}
	}

	r.tunnels[tunnel.id] = append(r.tunnels[tunnel.id], apiConn)
	r.outgoingTunnels[tunnel.id] = tunnel

	return tunnel, nil
}

// SendData passes application payload through an existing tunnel, either incoming or outgoing taking care of
// message packing and encryption.
func (r *Router) SendData(tunnelID uint32, payload []byte) (err error) {
	relayData := p2p.RelayTunnelData{
		Data: payload,
	}

	buf := make([]byte, p2p.RelayMessageSize)
	if tunnel, ok := r.outgoingTunnels[tunnelID]; ok {
		var n int
		tunnel.counter, n, err = p2p.PackRelayMessage(buf, tunnel.counter, &relayData)
		if err != nil {
			return err
		}

		var encryptedMsg []byte
		encryptedMsg, err = tunnel.EncryptRelayMsg(buf[:n])
		if err != nil {
			return err
		}

		return tunnel.link.sendRelay(tunnelID, encryptedMsg)
	} else if tunnelSegment, ok := r.incomingTunnels[tunnelID]; ok {
		var n int
		tunnelSegment.counter, n, err = p2p.PackRelayMessage(buf, tunnelSegment.counter, &relayData)
		if err != nil {
			return err
		}

		var encryptedMsg []byte
		encryptedMsg, err = p2p.EncryptRelay(buf[:n], tunnelSegment.dhShared)
		if err != nil {
			return err
		}

		return tunnelSegment.prevHopLink.sendRelay(tunnelID, encryptedMsg)
	}

	return ErrInvalidTunnel
}

func (r *Router) SendCover(coverSize uint16) (err error) {
	// TODO: implement
	return
}

// sendMsgToAPI sends a api.Message to all api.Connection that are registered for the given tunnel ID
func (r *Router) sendMsgToAPI(tunnelID uint32, msg api.Message) (err error) {
	apiConns, ok := r.tunnels[tunnelID]
	if !ok {
		return ErrInvalidTunnel
	}
	for _, apiConn := range apiConns {
		sendError := apiConn.Send(msg)
		log.Printf("Sent message to API")
		if sendError != nil {
			sendError = apiConn.Terminate()
			if sendError != nil {
				log.Printf("Error terminating API conn: %v\n", sendError)
			}
			removeErr := r.RemoveAPIConnection(apiConn)
			if removeErr != nil {
				log.Printf("Error removing API conn: %v\n", removeErr)
			}
		}
	}

	return nil
}

// sendMsgToAllAPI broadcasts an api.Message to all api.Connection which are known to the Router.
// Useful for announcing incoming onion tunnels.
func (r *Router) sendMsgToAllAPI(msg api.Message) (err error) {
	for _, apiConn := range r.apiConnections {
		sendError := apiConn.Send(msg)
		if sendError != nil {
			sendError = apiConn.Terminate()
			if sendError != nil {
				log.Printf("Error terminating API conn: %v\n", sendError)
			}
			removeErr := r.RemoveAPIConnection(apiConn)
			if removeErr != nil {
				log.Printf("Error removing API conn: %v\n", removeErr)
			}
		}
	}

	return nil
}

// sendDataToAPI is a convenience function to send application data received on a tunnel back to all API connections
// that are registered for this tunnel.
func (r *Router) sendDataToAPI(tunnelID uint32, data []byte) (err error) {
	apiMessage := api.OnionTunnelData{
		TunnelID: tunnelID,
		Data:     data,
	}

	// currently, we only only get an error if the tunnel ID is invalid
	err = r.sendMsgToAPI(tunnelID, &apiMessage)
	return err
}

// RegisterIncomingConnection takes care of tracking the state of an incoming tunnel and announcing it to all API connections.
func (r *Router) RegisterIncomingConnection(tunnel *tunnelSegment) (err error) {
	if _, ok := r.tunnels[tunnel.prevHopTunnelID]; !ok {
		return ErrInvalidTunnel
	}

	r.tunnels[tunnel.prevHopTunnelID] = make([]*api.Connection, len(r.apiConnections))
	copy(r.tunnels[tunnel.prevHopTunnelID], r.apiConnections)
	r.incomingTunnels[tunnel.prevHopTunnelID] = tunnel

	incomingMsg := api.OnionTunnelIncoming{
		TunnelID: tunnel.prevHopTunnelID,
	}

	return r.sendMsgToAllAPI(&incomingMsg)
}

// RemoveAPIConnection unregisters an api.Connection from the router and all existing tunnels.
func (r *Router) RemoveAPIConnection(apiConn *api.Connection) (err error) {
	for tunnelID := range r.tunnels {
		err = r.RemoveAPIConnectionFromTunnel(tunnelID, apiConn)
	}

	for i, conn := range r.apiConnections {
		if conn == apiConn {
			r.apiConnections = append(r.apiConnections[:i], r.apiConnections[i+1:]...)
			break
		}
	}

	return err
}

// RemoveAPIConnectionFromTunnel unregisters an api.Connection as a listener on the given tunnel.
// Will also initiate tunnel teardown if no api.Connection is registered for the tunnel anymore.
func (r *Router) RemoveAPIConnectionFromTunnel(tunnelID uint32, apiConn *api.Connection) (err error) {
	if _, ok := r.tunnels[tunnelID]; !ok {
		return
	}

	for i, conn := range r.tunnels[tunnelID] {
		if conn == apiConn {
			r.tunnels[tunnelID] = append(r.tunnels[tunnelID][:i], r.tunnels[tunnelID][i+1:]...)
			break
		}
	}

	if len(r.tunnels[tunnelID]) == 0 { // the last API connection unregistered, we tear down the tunnel now
		if outgoingTunnel, ok := r.outgoingTunnels[tunnelID]; ok {
			err = outgoingTunnel.Close()
		} else if incomingTunnel, ok := r.incomingTunnels[tunnelID]; ok {
			err = incomingTunnel.Close()
		}
	}

	return err
}

// newTunnelID generates a new, non-existing unique tunnel ID
func (r *Router) newTunnelID() (tunnelID uint32) {
	random := mathRand.New(mathRand.NewSource(time.Now().UnixNano())) //nolint:gosec // pseudo-rand is good enough. We just need uniqueness.
	tunnelID = random.Uint32()
	// ensure that tunnelID is unique
	for {
		if _, ok := r.tunnels[tunnelID]; ok {
			tunnelID = random.Uint32() // non unique tunnel ID
			continue
		}
		break
	}

	r.tunnels[tunnelID] = make([]*api.Connection, 0)

	return tunnelID
}

// removeLink removes a Link from the Router state
func (r *Router) removeLink(link *Link) {
	for i, ln := range r.links {
		if ln == link {
			r.links = append(r.links[:i], r.links[i+1:]...)
			break
		}
	}
}

// RemoveTunnel completely unregisters a tunnel from the router closing associated links if no tunnel uses them anymore
// and shutting down all tunnel handler routines.
func (r *Router) RemoveTunnel(tunnelID uint32) (err error) {
	if _, ok := r.tunnels[tunnelID]; !ok {
		return
	}
	for _, link := range r.links {
		if link.hasTunnel(tunnelID) {
			link.removeTunnel(tunnelID)
			if link.isUnused() {
				link.Close()
			}
		}
	}

	delete(r.tunnels, tunnelID)
	delete(r.outgoingTunnels, tunnelID)
	delete(r.incomingTunnels, tunnelID)

	return err
}

// CreateLink opens a new Link connection to the give peer and starts the Link handler routine.
func (r *Router) CreateLink(address net.IP, port uint16) (link *Link, err error) {
	link, err = newLink(address, port)
	if err != nil {
		return nil, err
	}

	r.links = append(r.links, link)

	go r.handleLink(link)

	return link, nil
}

// CreateLinkFromExistingConn adds an existing TLS connection to the Router state and starts the Link handler routine.
func (r *Router) CreateLinkFromExistingConn(conn net.Conn) (link *Link, err error) {
	link = newLinkFromExistingConn(conn)

	r.links = append(r.links, link)

	go r.handleLink(link)

	return link, nil
}

// GetLink checks if a Link exists to the given peer and returns it. If none exists will return nil, false.
func (r *Router) GetLink(address net.IP, port uint16) (link *Link, ok bool) {
	for _, link := range r.links {
		if link.address.Equal(address) && link.port == port {
			return link, true
		}
	}

	return nil, false
}

// GetOrCreateLink returns a Link to the given peer creating a new one if none exists.
func (r *Router) GetOrCreateLink(address net.IP, port uint16) (link *Link, err error) {
	link, ok := r.GetLink(address, port)
	if ok {
		return link, nil
	}

	return r.CreateLink(address, port)
}

// HandleOutgoingTunnel is a goroutine handling all traffic for a Tunnel that was initiated by this peer.
func (r *Router) HandleOutgoingTunnel(tunnel *Tunnel) {
	// This is the handler go routine for outgoing tunnels that we initiated.
	// It is assumed that the handshake with the peers is completed and the tunnel is fully initiated at this point!
	defer func() {
		err := r.RemoveTunnel(tunnel.id)
		if err != nil {
			log.Printf("Error removing tunnel from link with ID %v: %v\n", tunnel.id, err)
		}
	}()

	dataOut, ok := tunnel.link.getDataOut(tunnel.id)
	if !ok {
		log.Printf("Failed to get data channel for outgoing tunnel %v\n", tunnel.id)
		return
	}

	for {
		select {
		case msg, channelOpen := <-dataOut:
			if !channelOpen {
				return
			}

			hdr := msg.hdr
			switch hdr.Type {
			case p2p.TypeTunnelRelay:
				relayHdr, decryptedRelayMsg, ok, err := tunnel.DecryptRelayMessage(msg.body)
				if err != nil {
					log.Printf("Error decrypting relay message on outgoing tunnel %v\n", tunnel.id)
					return
				}

				if ok { // message is meant for us from a hop
					// replay protection
					if relayHdr.GetCounter() <= tunnel.counter {
						log.Printf("Received message with invalid counter. Terminating tunnel.")
						return
					}

					// update message counter
					tunnel.counter = relayHdr.GetCounter()

					switch relayHdr.RelayType {
					case p2p.RelayTypeTunnelData:
						dataMsg := p2p.RelayTunnelData{}
						err = dataMsg.Parse(decryptedRelayMsg)
						if err != nil {
							log.Printf("Error parsing relay data message on outgoing tunnel %v\n", tunnel.id)
							return
						}

						err = r.sendDataToAPI(hdr.TunnelID, dataMsg.Data)
						if err != nil {
							log.Printf("Error sending incoming data to API for outgoing tunnel %v\n", tunnel.id)
							return
						}

					default:
						log.Printf("Received invalid subtype of relay message on outgoing tunnel %v\n", tunnel.id)
						return
					}
				} else {
					// we received a non-decryptable relay message, tear down the tunnel
					log.Printf("Received un-decryptable relay message on outgoing tunnel %v\n", tunnel.id)
					_ = tunnel.link.sendDestroyTunnel(tunnel.id)
					// in case of an error here we cannot really do much apart from tearing down the tunnel anyway
					return
				}

			case p2p.TypeTunnelDestroy:
				// since we are the end of the tunnel we don't need to pass the destroy message along we just need
				// to gracefully tear down our tunnel and announce it to the API
				err := r.sendMsgToAPI(tunnel.ID(), &api.OnionTunnelDestroy{
					TunnelID: tunnel.ID(),
				})
				if err != nil {
					log.Printf("Error announcing tunnel destroy for ID %v to api %v\n", tunnel.ID(), err)
				}
				return

			default: // since we assume the circuit to be fully built we cannot accept any other message
				log.Printf("Received invalid message on outgoing tunnel %v\n", tunnel.id)
				return
			}

		case <-tunnel.link.Quit:
			return
		}
	}
}

// handleIncomingTunnelRelayMsg processes an incoming p2p.Message of type p2p.TypeTunnelRelay on an incoming tunnel.
// Handles p2p.RelayTypeTunnelExtend by extending the current tunnel.
// Handles p2p.RelayTypeTunnelData by passing the received application payload to all registered API connections.
func (r *Router) handleIncomingTunnelRelayMsg(buf []byte, dataChanNextHop chan message, tunnel *tunnelSegment, msgHdr *p2p.Header, msgData []byte) (err error) {
	var ok bool
	var decryptedRelayMsg []byte
	ok, decryptedRelayMsg, err = p2p.DecryptRelay(msgData, tunnel.dhShared)
	if err != nil { // error when decrypting
		return
	}

	if ok { // relay message is meant for us
		relayHdr := p2p.RelayHeader{}
		err = relayHdr.Parse(decryptedRelayMsg[:p2p.RelayHeaderSize])
		if err != nil {
			return
		}

		// replay protection
		if relayHdr.GetCounter() <= tunnel.counter {
			log.Printf("Received message with invalid counter. Terminating tunnel.")
			return
		}

		// update message counter
		tunnel.counter = relayHdr.GetCounter()

		switch relayHdr.RelayType {
		case p2p.RelayTypeTunnelData:
			dataMsg := p2p.RelayTunnelData{}
			err = dataMsg.Parse(decryptedRelayMsg[p2p.RelayHeaderSize:relayHdr.Size])
			if err != nil {
				return err
			}

			// we received a valid data packed check if this was the first data message on this tunnel,
			// if so announce it to the API as tunnel incoming

			if _, ok := r.tunnels[msgHdr.TunnelID]; !ok {
				return ErrInvalidTunnel
			}

			if len(r.tunnels[msgHdr.TunnelID]) == 0 {
				err = r.RegisterIncomingConnection(tunnel)
				if err != nil {
					return err
				}
			}

			// currently, we only only get an error if the tunnel ID is invalid
			err = r.sendDataToAPI(tunnel.prevHopTunnelID, dataMsg.Data)
			if err != nil {
				return err
			}

		case p2p.RelayTypeTunnelExtend: // this be quite interesting
			extendMsg := p2p.RelayTunnelExtend{}
			err = extendMsg.Parse(decryptedRelayMsg[p2p.RelayHeaderSize:relayHdr.Size])
			if err != nil {
				return err
			}

			var nextLink *Link
			nextLink, err = r.GetOrCreateLink(extendMsg.Address, extendMsg.Port)
			if err != nil {
				return err
			}

			tunnel.nextHopLink = nextLink
			tunnel.nextHopTunnelID = r.newTunnelID()
			err = nextLink.register(tunnel.nextHopTunnelID, dataChanNextHop)
			if err != nil {
				return err
			}

			createMsg := tunnelCreateMsgFromRelayTunnelExtendMsg(&extendMsg)
			err = tunnel.nextHopLink.sendMsg(tunnel.nextHopTunnelID, &createMsg)
			if err != nil {
				return err
			}

			select {
			case created := <-dataChanNextHop:
				if created.hdr.Type != p2p.TypeTunnelCreated {
					return p2p.ErrInvalidMessage
				}

				createdMsg := p2p.TunnelCreated{}
				err = createdMsg.Parse(created.body)
				if err != nil {
					return err
				}

				extendedMsg := relayTunnelExtendedMsgFromTunnelCreatedMsg(&createdMsg)
				var n int
				tunnel.counter, n, err = p2p.PackRelayMessage(buf, tunnel.counter, &extendedMsg)
				if err != nil {
					return err
				}

				var encryptedExtended []byte
				encryptedExtended, err = p2p.EncryptRelay(buf[:n], tunnel.dhShared)
				if err != nil {
					return err
				}

				err = tunnel.prevHopLink.sendRelay(tunnel.prevHopTunnelID, encryptedExtended)
				if err != nil {
					return err
				}

			case <-time.After(time.Duration(r.cfg.BuildTimeout) * time.Second): // timeout
				return ErrTimedOut
			}
		default:
			return p2p.ErrInvalidMessage
		}
	} else {
		// relay message is not meant for us
		if tunnel.nextHopLink != nil { // simply pass it along with one layer of encryption removed
			err = tunnel.nextHopLink.sendRelay(tunnel.nextHopTunnelID, decryptedRelayMsg)
			if err != nil {
				return err
			}
		} else { // we received an invalid relay message
			return p2p.ErrInvalidMessage
		}
	}

	return err
}

// handleTunnelSegment is a goroutine handling all incoming traffic on an incoming tunnel where this peer is either the
// last hop in the tunnel or an intermediate hop. Handles tunnel extensions and relay messages that should be passed
// through the tunnel.
func (r *Router) handleTunnelSegment(tunnel *tunnelSegment, errOut chan error) {
	// This is the handler go routine for incoming tunnels that either are terminated by us or where we are just
	// an in-between hop. The handshake of the previous hop to us is assumed to be done we can, however, receive
	// TunnelExtend commands.
	dataChanPrevHop := make(chan message, 5)
	dataChanNextHop := make(chan message, 5)
	err := tunnel.prevHopLink.register(tunnel.prevHopTunnelID, dataChanPrevHop)
	if err != nil {
		errOut <- err
		return
	}
	defer func() {
		removeErr := r.RemoveTunnel(tunnel.prevHopTunnelID)
		if removeErr != nil {
			log.Printf("Error removing tunnel from link with ID %v: %v\n", tunnel.prevHopTunnelID, removeErr)
		}
		if tunnel.nextHopLink != nil {
			removeErr = r.RemoveTunnel(tunnel.nextHopTunnelID)
			if removeErr != nil {
				log.Printf("Error removing tunnel from link with ID %v: %v\n", tunnel.nextHopTunnelID, removeErr)
			}
		}
	}()

	buf := make([]byte, p2p.MessageSize)

	for {
		select {
		case msg, channelOpen := <-dataChanPrevHop: // we receive a message from the previous hop
			if !channelOpen {
				return
			}

			hdr := msg.hdr
			data := msg.body
			switch hdr.Type {
			case p2p.TypeTunnelRelay:
				err = r.handleIncomingTunnelRelayMsg(buf, dataChanNextHop, tunnel, &hdr, data)
				if err != nil {
					log.Printf("Error handling incoming relay message: %v\n", err)
					return
				}
			case p2p.TypeTunnelDestroy:
				// we pass the destroy message along and tear down
				if tunnel.nextHopLink != nil {
					err = tunnel.nextHopLink.sendDestroyTunnel(tunnel.nextHopTunnelID)
					if err != nil {
						errOut <- err
					}
				}
				err = r.sendMsgToAPI(tunnel.prevHopTunnelID, &api.OnionTunnelDestroy{
					TunnelID: tunnel.prevHopTunnelID,
				})
				if err != nil {
					errOut <- err
				}
				return
			default: // any other message is illegal here
				errOut <- p2p.ErrInvalidMessage
				return
			}
		case msg, channelOpen := <-dataChanNextHop: // we receive a message from the next hop
			if !channelOpen {
				return
			}

			hdr := msg.hdr
			data := msg.body
			switch hdr.Type {
			case p2p.TypeTunnelRelay: // simply add one layer of encryption and pass it along
				var encryptedMsg []byte
				encryptedMsg, err = p2p.EncryptRelay(data, tunnel.dhShared)
				if err != nil {
					errOut <- err
					return
				}

				err = tunnel.prevHopLink.sendRelay(tunnel.prevHopTunnelID, encryptedMsg)
				if err != nil {
					errOut <- err
					return
				}

			case p2p.TypeTunnelDestroy:
				err = tunnel.prevHopLink.sendDestroyTunnel(tunnel.prevHopTunnelID)
				if err != nil {
					errOut <- err
				}
				err = r.sendMsgToAPI(tunnel.prevHopTunnelID, &api.OnionTunnelDestroy{
					TunnelID: tunnel.prevHopTunnelID,
				})
				if err != nil {
					errOut <- err
				}
				return

			default: // any other message is illegal here
				errOut <- p2p.ErrInvalidMessage
				return
			}

		case <-tunnel.prevHopLink.Quit:
			if tunnel.nextHopLink != nil {
				tunnel.nextHopLink.Close()
			}
			return
		case <-tunnel.quit:
			return
		}
	}
}

// handleLink is the goroutine handler for a Link that reads from the underlying tls.Conn and passes received p2p.Message
// to the respective tunnel handler via the registered Link.dataOut channel.
func (r *Router) handleLink(link *Link) {
	goRoutineErr := make(chan error, 10)
	shuttingDown := false
	go func() {
		select {
		case <-link.Quit:
			log.Printf("Terminating link")
			shuttingDown = true
			r.removeLink(link)
			_ = link.destroy()
			return
		case err := <-goRoutineErr:
			log.Printf("Error in goroutine: %v\n", err)
		}
	}()

	for {
		msg, err := link.readMsg()
		if err != nil {
			if shuttingDown || err == io.EOF {
				return // connection closed cleanly
			}
			log.Printf("Error reading message body: %v, ignoring message", err)
			err = r.RemoveTunnel(msg.hdr.TunnelID)
			if err != nil {
				log.Printf("Error removing tunnel with ID: %v, %v\n", msg.hdr.TunnelID, err)
			}
			continue
		}

		dataOut, ok := link.dataOut[msg.hdr.TunnelID]
		if ok {
			dataOut <- msg
		} else {
			// we receive the first message on this link for a yet unknown tunnel

			hdr, data := msg.hdr, msg.body

			// the first message for a new tunnel MUST be TUNNEL_CREATE
			if hdr.Type != p2p.TypeTunnelCreate {
				log.Printf("Error: received first message for new tunnel that is not tunnel create")
				continue
			}
			msg := p2p.TunnelCreate{}
			err = msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing tunnel create message: %v", err)
				err = r.RemoveTunnel(hdr.TunnelID)
				if err != nil {
					log.Printf("Error removing tunnel with ID: %v, %v\n", hdr.TunnelID, err)
				}
				continue
			}

			dhShared, tunnelCreated, err := handleTunnelCreate(&msg, r.cfg)
			if err != nil {
				log.Printf("Error handling tunnel create message: %v", err)
				err = r.RemoveTunnel(hdr.TunnelID)
				if err != nil {
					log.Printf("Error removing tunnel with ID: %v, %v\n", hdr.TunnelID, err)
				}
				continue
			}

			if _, ok := r.tunnels[hdr.TunnelID]; ok {
				log.Printf("Received tunnel create for existing tunnel id")
				continue
			}
			r.tunnels[hdr.TunnelID] = make([]*api.Connection, 0)

			receivingTunnel := tunnelSegment{
				prevHopTunnelID: hdr.TunnelID,
				prevHopLink:     link,
				dhShared:        dhShared,
				quit:            make(chan struct{}),
			}
			err = link.sendMsg(hdr.TunnelID, tunnelCreated)
			if err != nil {
				log.Printf("Error sending tunnel created message: %v", err)
				continue
			}

			// now we start the normal message handling for this tunnel
			go r.handleTunnelSegment(&receivingTunnel, goRoutineErr)
		}
	}
}
