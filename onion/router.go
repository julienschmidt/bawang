// Package onion provides the onion routing logic.
package onion

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"io"
	"log"
	mathRand "math/rand"
	"net"
	"time"

	"golang.org/x/crypto/nacl/box"

	"bawang/api"
	"bawang/config"
	"bawang/p2p"
)

type Router struct {
	cfg *config.Config

	links []*Link

	// maps which api connections listen on which tunnels in addition to keeping track of existing tunnels
	tunnels map[uint32][]*api.Connection

	outgoingTunnels map[uint32]*Tunnel
	incomingTunnels map[uint32]*TunnelSegment

	apiConnections []*api.Connection
}

// here are the functions used by the module communicating with the API

func NewRouter(cfg *config.Config) *Router {
	return &Router{
		cfg: cfg,
	}
}

func (r *Router) RegisterAPIConnection(apiConn *api.Connection) {
	r.apiConnections = append(r.apiConnections, apiConn)
}

func (r *Router) SendCover(coverSize uint16) (err error) {
	// TODO: implement
	return
}

func (r *Router) BuildTunnel(hops []*Peer, apiConn *api.Connection) (tunnel *Tunnel, err error) {
	if len(hops) < 3 {
		return nil, ErrNotEnoughHops
	}

	msgBuf := make([]byte, p2p.MaxSize)

	// generate a new, unique tunnel ID
	tunnelID := r.newTunnelID()

	// first we fetch us a link connection to the first hop
	link, err := r.GetOrCreateLink(hops[0].Address, hops[0].Port)
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

	case <-time.After(time.Duration(r.cfg.CreateTimeout) * time.Second):
		return nil, ErrTimedOut
	}

	// handshake with first hop is done, do the remaining ones
	for _, hop := range hops[1:] {
		dhPriv, extendMsg, err := CreateTunnelExtend(hop.HostKey, hop.Address, hop.Port)
		if err != nil {
			return nil, err
		}

		var n int
		tunnel.Counter, n, err = p2p.PackRelayMessage(msgBuf, tunnel.Counter, extendMsg)
		if err != nil {
			return nil, err
		}

		// layer on encryption
		packedMsg := msgBuf[:n]
		for j := len(tunnel.Hops) - 1; j > 1; j-- {
			packedMsg, err = p2p.EncryptRelay(packedMsg, &tunnel.Hops[j].DHShared)
			if err != nil {
				return nil, err
			}
		}

		err = link.SendRaw(tunnelID, p2p.TypeTunnelRelay, packedMsg)
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
			relayHdr, decryptedRelayMsg, ok, err := tunnel.DecryptRelayMessage(extended.payload)
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

			tunnel.Hops = append(tunnel.Hops, &Peer{
				DHShared: dhShared,
				Port:     hops[0].Port,
				Address:  hops[0].Address,
				HostKey:  hops[0].HostKey,
			})

			break
		case <-time.After(time.Duration(r.cfg.CreateTimeout) * time.Second):
			return nil, ErrTimedOut
		}
	}

	r.tunnels[tunnel.ID] = append(r.tunnels[tunnel.ID], apiConn)
	r.outgoingTunnels[tunnel.ID] = tunnel
	return tunnel, nil
}

func (r *Router) SendData(tunnelID uint32, payload []byte) (err error) {
	relayData := p2p.RelayTunnelData{
		Data: payload,
	}

	buf := make([]byte, p2p.MaxRelaySize)
	if tunnel, ok := r.outgoingTunnels[tunnelID]; ok {
		var n int
		tunnel.Counter, n, err = p2p.PackRelayMessage(buf, tunnel.Counter, &relayData)
		if err != nil {
			return err
		}

		var encryptedMsg []byte
		encryptedMsg, err = tunnel.EncryptRelayMsg(buf[:n])
		if err != nil {
			return err
		}

		return tunnel.Link.SendRaw(tunnelID, p2p.TypeTunnelRelay, encryptedMsg)
	} else if tunnelSegment, ok := r.incomingTunnels[tunnelID]; ok {
		var n int
		tunnelSegment.Counter, n, err = p2p.PackRelayMessage(buf, tunnelSegment.Counter, &relayData)
		if err != nil {
			return err
		}

		var encryptedMsg []byte
		encryptedMsg, err = p2p.EncryptRelay(buf[:n], tunnelSegment.DHShared)
		if err != nil {
			return err
		}

		return tunnelSegment.PrevHopLink.SendRaw(tunnelID, p2p.TypeTunnelRelay, encryptedMsg)
	}

	return ErrInvalidTunnel
}

func (r *Router) sendMsgToAllAPI(msg api.Message) (err error) {
	for _, apiConn := range r.apiConnections {
		sendError := apiConn.Send(msg)
		if sendError != nil {
			sendError = apiConn.Terminate()
			r.RemoveAPIConnection(apiConn)
		}
	}

	return nil
}

func (r *Router) sendMsgToAPI(tunnelID uint32, msg api.Message) (err error) {
	apiConns, ok := r.tunnels[tunnelID]
	if !ok {
		return ErrInvalidTunnel
	}
	for _, apiConn := range apiConns {
		sendError := apiConn.Send(msg)
		if sendError != nil {
			sendError = apiConn.Terminate()
			r.RemoveAPIConnection(apiConn)
		}
	}

	return nil
}

func (r *Router) RegisterIncomingConnection(tunnelID uint32) (err error) {
	if _, ok := r.tunnels[tunnelID]; !ok {
		return ErrInvalidTunnel
	}

	r.tunnels[tunnelID] = make([]*api.Connection, len(r.apiConnections))
	copy(r.tunnels[tunnelID], r.apiConnections)

	incomingMsg := api.OnionTunnelIncoming{
		TunnelID: tunnelID,
	}

	return r.sendMsgToAllAPI(&incomingMsg)
}

func (r *Router) RemoveAPIConnection(apiConn *api.Connection) {
	for tunnelID := range r.tunnels {
		r.RemoveAPIConnectionFromTunnel(tunnelID, apiConn)
	}

	for i, conn := range r.apiConnections {
		if conn == apiConn {
			r.apiConnections = append(r.apiConnections[:i], r.apiConnections[i+1:]...)
			break
		}
	}
}

func (r *Router) RemoveAPIConnectionFromTunnel(tunnelID uint32, apiConn *api.Connection) {
	if _, ok := r.tunnels[tunnelID]; !ok {
		return
	}

	for i, conn := range r.tunnels[tunnelID] {
		if conn == apiConn {
			r.tunnels[tunnelID] = append(r.tunnels[tunnelID][:i], r.tunnels[tunnelID][i+1:]...)
			break
		}
	}
}

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

func (r *Router) RemoveTunnel(tunnelID uint32) {
	if _, ok := r.tunnels[tunnelID]; !ok {
		return
	}

	// TODO: determine if we can even send an error message to the api in a way to let them know the tunnel is gone
	// onionErrMsg := api.OnionError{
	// 	TunnelID: tunnelID,
	// 	RequestType: api.TypeOnionTunnelReady,
	// }
	// err = onion.SendMsgToAPI(tunnelID, &onionErrMsg)

	for _, link := range r.links {
		if link.HasTunnel(tunnelID) {
			link.RemoveTunnel(tunnelID)
		}
	}

	delete(r.tunnels, tunnelID)
}

func (r *Router) CreateLink(address net.IP, port uint16) (link *Link, err error) {
	link, err = newLink(address, port)
	if err != nil {
		return nil, err
	}

	r.links = append(r.links, link)

	return link, nil
}

func (r *Router) CreateLinkFromExistingConn(address net.IP, port uint16, conn net.Conn) (link *Link, err error) {
	link = newLinkFromExistingConn(address, port, conn)

	r.links = append(r.links, link)

	return link, nil
}

func (r *Router) GetLink(address net.IP, port uint16) (link *Link, ok bool) {
	for _, link := range r.links {
		if link.Address.Equal(address) && link.Port == port {
			return link, true
		}
	}

	return nil, false
}

func (r *Router) GetOrCreateLink(address net.IP, port uint16) (link *Link, err error) {
	link, ok := r.GetLink(address, port)
	if ok {
		return link, nil
	}

	return r.CreateLink(address, port)
}

func (r *Router) HandleOutgoingTunnel(tunnel *Tunnel, dataOut chan message, errOut chan error) {
	// This is the handler go routine for outgoing tunnels that we initiated.
	// It is assumed that the handshake with the peers is completed and the tunnel is fully initiated at this point!
	defer tunnel.Link.RemoveTunnel(tunnel.ID)
	defer r.RemoveTunnel(tunnel.ID)

	for {
		select {
		case msg, channelOpen := <-dataOut:
			if !channelOpen {
				return
			}

			hdr := msg.hdr
			switch hdr.Type {
			case p2p.TypeTunnelRelay:
				relayHdr, decryptedRelayMsg, ok, err := tunnel.DecryptRelayMessage(msg.payload)
				if err != nil {
					errOut <- err
					return
				}

				if ok { // message is meant for us from a hop
					switch relayHdr.RelayType {
					case p2p.RelayTypeTunnelData:
						dataMsg := p2p.RelayTunnelData{}
						err = dataMsg.Parse(decryptedRelayMsg)
						if err != nil {
							errOut <- err
							return
						}

						apiMessage := api.OnionTunnelData{
							TunnelID: tunnel.ID,
							Data:     dataMsg.Data,
						}

						err = r.sendMsgToAPI(tunnel.ID, &apiMessage)
						// TODO: figure out if we want to really do nothing here with that error

					default:
						errOut <- p2p.ErrInvalidMessage
						return
					}
				}

				// TODO: decide what to do on an non-encryptable relay message

			case p2p.TypeTunnelDestroy:
				// since we are the end of the tunnel we don't need to pass the destroy message along we just need
				// to gracefully tear down our tunnel
				return

			default: // since we assume the circuit to be fully built we cannot accept any other message
				errOut <- p2p.ErrInvalidMessage
				return
			}

		case <-tunnel.Link.Quit:
			return
		}
	}
}

func (r *Router) HandleTunnelSegment(tunnel *TunnelSegment, errOut chan error) {
	// This is the handler go routine for incoming tunnels that either are terminated by us or where we are just
	// an in-between hop. The handshake of the previous hop to us is assumed to be done we can, however, receive
	// TunnelExtend commands.
	dataChanPrevHop := make(chan message, 5) // TODO: determine buffer size
	dataChanNextHop := make(chan message, 5)
	err := tunnel.PrevHopLink.register(tunnel.PrevHopTunnelID, dataChanPrevHop)
	if err != nil {
		errOut <- err
		return
	}
	defer tunnel.PrevHopLink.RemoveTunnel(tunnel.PrevHopTunnelID)
	defer r.RemoveTunnel(tunnel.PrevHopTunnelID)
	defer r.RemoveTunnel(tunnel.NextHopTunnelID)

	for {
		select {
		case msg, channelOpen := <-dataChanPrevHop: // we receive a message from the previous hop
			if !channelOpen {
				return
			}

			hdr := msg.hdr
			data := msg.payload
			switch hdr.Type {
			case p2p.TypeTunnelRelay:
				var ok bool
				var decryptedRelayMsg []byte
				ok, decryptedRelayMsg, err = p2p.DecryptRelay(data, tunnel.DHShared)
				if err != nil { // error when decrypting
					errOut <- err
					return
				}

				if ok { // relay message is meant for us
					relayHdr := p2p.RelayHeader{}
					err = relayHdr.Parse(decryptedRelayMsg)
					if err != nil {
						return
					}

					switch relayHdr.RelayType {
					case p2p.RelayTypeTunnelData:
						dataMsg := p2p.RelayTunnelData{}
						err = dataMsg.Parse(decryptedRelayMsg[p2p.RelayHeaderSize:relayHdr.Size])
						if err != nil {
							errOut <- err
							return
						}

						// we received a valid data packed check if this was the first data message on this tunnel,
						// if so announce it to the API as tunnel incoming

						if _, ok := r.tunnels[hdr.TunnelID]; !ok {
							errOut <- ErrInvalidTunnel
							return
						}

						if len(r.tunnels[hdr.TunnelID]) == 0 {
							err = r.RegisterIncomingConnection(hdr.TunnelID)
							if err != nil {
								errOut <- err
								return
							}
						}

						apiMessage := api.OnionTunnelData{
							TunnelID: tunnel.PrevHopTunnelID,
							Data:     dataMsg.Data,
						}

						err = r.sendMsgToAPI(tunnel.PrevHopTunnelID, &apiMessage)
						// TODO: figure out if we want to really do nothing here with that error

					case p2p.RelayTypeTunnelExtend: // this be quite interesting
						extendMsg := p2p.RelayTunnelExtend{}
						err = extendMsg.Parse(decryptedRelayMsg)
						if err != nil {
							errOut <- err
							return
						}

						var nextLink *Link
						nextLink, err = r.GetOrCreateLink(extendMsg.Address, extendMsg.Port)
						if err != nil {
							errOut <- err
							return
						}

						tunnel.NextHopLink = nextLink
						tunnel.NextHopTunnelID = r.newTunnelID()
						createMsg := CreateMsgFromExtendMsg(extendMsg)
						err = tunnel.NextHopLink.Send(tunnel.NextHopTunnelID, &createMsg)
						if err != nil {
							errOut <- err
							return
						}

						select {
						case created := <-dataChanNextHop:
							if created.hdr.Type != p2p.TypeTunnelCreated {
								errOut <- p2p.ErrInvalidMessage
								return
							}

							createdMsg := p2p.TunnelCreated{}
							err = createdMsg.Parse(created.payload)
							if err != nil {
								errOut <- err
								return
							}

							extendedMsg := ExtendedMsgFromCreatedMsg(createdMsg)
							packedExtended := make([]byte, extendedMsg.PackedSize())
							var n int
							n, err = extendedMsg.Pack(packedExtended)
							if err != nil {
								errOut <- err
								return
							}

							var encryptedExtended []byte
							encryptedExtended, err = p2p.EncryptRelay(packedExtended[:n], tunnel.DHShared)
							if err != nil {
								errOut <- err
								return
							}

							err = tunnel.PrevHopLink.SendRaw(tunnel.PrevHopTunnelID, p2p.TypeTunnelRelay, encryptedExtended)
							if err != nil {
								errOut <- err
								return
							}

						case <-time.After(time.Duration(r.cfg.CreateTimeout) * time.Second): // timeout
							errOut <- ErrTimedOut
							return
						}

						// TODO: finish implementing
					default:
						errOut <- p2p.ErrInvalidMessage
						return
					}

				} else {
					// relay message is not meant for us
					if tunnel.NextHopLink != nil { // simply pass it along with one layer of encryption removed
						err = tunnel.NextHopLink.SendRaw(tunnel.NextHopTunnelID, p2p.TypeTunnelRelay, decryptedRelayMsg)
						if err != nil {
							errOut <- err
							return
						}
					} else { // we received an invalid relay message
						errOut <- p2p.ErrInvalidMessage
						return
					}
				}

			case p2p.TypeTunnelDestroy:
				// we pass the destroy message along and tear down
				// TODO: send onion error message to API here
				err = tunnel.NextHopLink.SendDestroyTunnel(tunnel.NextHopTunnelID)
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
			data := msg.payload
			switch hdr.Type {
			case p2p.TypeTunnelRelay: // simply add one layer of encryption and pass it along
				var encryptedMsg []byte
				encryptedMsg, err = p2p.EncryptRelay(data, tunnel.DHShared)
				if err != nil {
					errOut <- err
					return
				}

				err = tunnel.PrevHopLink.SendRaw(tunnel.PrevHopTunnelID, p2p.TypeTunnelRelay, encryptedMsg)
				if err != nil {
					errOut <- err
					return
				}

			case p2p.TypeTunnelDestroy:
				err = tunnel.PrevHopLink.SendDestroyTunnel(tunnel.PrevHopTunnelID)
				if err != nil {
					errOut <- err
				}
				return

			default: // any other message is illegal here
				errOut <- p2p.ErrInvalidMessage
				return
			}

		case <-tunnel.PrevHopLink.Quit:
			if tunnel.NextHopLink != nil {
				err = tunnel.NextHopLink.Destroy()
				if err != nil {
					errOut <- err
					return
				}
			}
			return
		}
	}
}

func (r *Router) HandleConnection(link *Link, errOut chan error) {
	var msgBuf [p2p.MaxSize]byte
	rd := bufio.NewReader(link.nc)

	for { // TODO: close on quit signal
		// read the message header
		var hdr p2p.Header
		err := hdr.Read(rd)
		if err != nil {
			if err == io.EOF {
				return
			}
			errOut <- err
			log.Printf("Error reading message header: %v", err)
			return
		}

		// ready message body
		data := msgBuf[:p2p.MaxSize]
		_, err = io.ReadFull(rd, data)
		if err != nil {
			errOut <- err
			log.Printf("Error reading message body: %v, ignoring message", err)
			// TODO: terminate the tunnel with read error
			r.RemoveTunnel(hdr.TunnelID)
			continue
		}

		_, ok := link.dataOut[hdr.TunnelID]
		if ok {
			link.dataOut[hdr.TunnelID] <- message{hdr, data}
		} else {
			// we receive the first message on this link for a tunnel we do not know yet
			if hdr.Type != p2p.TypeTunnelCreate { // the first message for a new tunnel MUST be Tunnel Create
				errOut <- p2p.ErrInvalidMessage
				log.Printf("Error: received first message for new tunnel that is not tunnel create")
				continue
			}
			msg := p2p.TunnelCreate{}
			err = msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing tunnel create message: %v", err)
				r.RemoveTunnel(hdr.TunnelID)
				continue
			}

			dhShared, tunnelCreated, err := HandleTunnelCreate(msg, r.cfg)
			if err != nil {
				log.Printf("Error handling tunnel create message: %v", err)
				r.RemoveTunnel(hdr.TunnelID)
				continue
			}

			if _, ok := r.tunnels[hdr.TunnelID]; ok {
				log.Printf("Received tunnel create for existing tunnel id")
				continue
			}
			r.tunnels[hdr.TunnelID] = make([]*api.Connection, 0)

			receivingTunnel := TunnelSegment{
				PrevHopTunnelID: hdr.TunnelID,
				PrevHopLink:     link,
				DHShared:        dhShared,
			}
			err = link.Send(hdr.TunnelID, tunnelCreated)
			if err != nil {
				errOut <- err
				log.Printf("Error sending tunnel created message: %v", err)
				continue
			}

			// now we start the normal message handling for this tunnel
			go r.HandleTunnelSegment(&receivingTunnel, errOut)
		}
	}
}
