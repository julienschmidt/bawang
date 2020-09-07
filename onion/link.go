package onion

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"bawang/api"
	"bawang/p2p"
)

var (
	ErrInvalidTunnel     = errors.New("invalid tunnel")
	ErrTimedOut          = errors.New("timed out")
	ErrAlreadyRegistered = errors.New("a listener is already registered for this tunnel ID")
)

type message struct {
	hdr     p2p.Header
	payload []byte
}

type Link struct {
	Address net.IP
	Port    uint16

	l      sync.Mutex // guards fields below
	msgBuf [p2p.MaxSize]byte
	nc     net.Conn
	rd     *bufio.Reader

	// data channels for communication with other goroutines
	dataOut map[uint32]chan message // output data channels for received messages with corresponding tunnel IDs
	Quit    chan struct{}
}

func NewLink(address net.IP, port uint16) (link *Link, err error) {
	link = &Link{
		Address: address,
		Port:    port,
		dataOut: make(map[uint32]chan message),
	}
	// output channels for corresponding tunnel IDs
	link.Quit = make(chan struct{})
	err = link.connect()
	if err != nil {
		return nil, err
	}
	return link, nil
}

func NewLinkFromExistingConn(address net.IP, port uint16, conn net.Conn) (link *Link) {
	return &Link{
		Address: address,
		Port:    port,
		nc:      conn,
		rd:      bufio.NewReader(conn),
		dataOut: make(map[uint32]chan message),
		Quit:    make(chan struct{}),
	}
}

func (link *Link) connect() (err error) {
	tlsConfig := tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // peers do use self-signed certs
	}
	// TODO: implement host key checking here
	link.nc, err = tls.Dial("tcp", link.Address.String()+":"+strconv.Itoa(int(link.Port)), &tlsConfig)
	if err != nil {
		log.Printf("Error opening tls connection to peer: %v", err)
		return
	}
	defer link.nc.Close()

	link.rd = bufio.NewReader(link.nc)

	return nil
}

func (link *Link) register(tunnelID uint32, dataOut chan message) (err error) {
	_, ok := link.dataOut[tunnelID]
	if ok {
		return ErrAlreadyRegistered
	}

	link.dataOut[tunnelID] = dataOut
	return nil
}

func (link *Link) HasTunnel(tunnelID uint32) (ok bool) {
	_, ok = link.dataOut[tunnelID]

	return
}

func (link *Link) RemoveTunnel(tunnelID uint32) {
	if _, ok := link.dataOut[tunnelID]; ok {
		close(link.dataOut[tunnelID])
	}
	delete(link.dataOut, tunnelID)
	// TODO: if there are no more listeners on this link we shut it down
}

func (link *Link) Destroy() (err error) {
	close(link.Quit)
	return
}

func (link *Link) SendDestroyTunnel(tunnelID uint32) (err error) {
	destroyMsg := p2p.TunnelDestroy{}
	err = link.Send(tunnelID, &destroyMsg)
	return
}

func (link *Link) SendRaw(tunnelID uint32, msgType p2p.Type, msg []byte) (err error) {
	if len(msg) > p2p.MaxSize-p2p.HeaderSize {
		return p2p.ErrInvalidMessage
	}
	data := link.msgBuf[:]
	header := p2p.Header{TunnelID: tunnelID, Type: msgType}
	header.Pack(data[:p2p.HeaderSize])
	copy(data[p2p.HeaderSize:len(msg)+p2p.HeaderSize], msg)

	link.l.Lock()
	_, err = link.nc.Write(data)
	link.l.Unlock()
	return err
}

func (link *Link) Send(tunnelID uint32, msg p2p.Message) (err error) {
	data := link.msgBuf[:]
	n, err := p2p.PackMessage(data, tunnelID, msg)
	if err != nil {
		return err
	}

	data = data[:n]
	link.l.Lock()
	_, err = link.nc.Write(data)
	link.l.Unlock()
	return err
}

func HandleOutgoingTunnel(tunnel *Tunnel, onion *Onion, dataOut chan message, cfg *Config, errOut chan error) {
	// This is the handler go routine for outgoing tunnels that we initiated.
	// It is assumed that the handshake with the peers is completed and the tunnel is fully initiated at this point!
	defer tunnel.Link.RemoveTunnel(tunnel.ID)
	defer onion.RemoveTunnel(tunnel.ID)

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

						err = onion.SendMsgToAPI(tunnel.ID, &apiMessage)
						// TODO: figure out if we want to really do nothing here with that error
					default:
						errOut <- p2p.ErrInvalidMessage
						return
					}

				} else {
					// TODO: decide what to do on an non-encryptable relay message
				}
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

func HandleTunnelSegment(tunnel *TunnelSegment, onion *Onion, cfg *Config, errOut chan error) {
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
	defer onion.RemoveTunnel(tunnel.PrevHopTunnelID)
	defer onion.RemoveTunnel(tunnel.NextHopTunnelID)

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

						if _, ok := onion.Tunnels[hdr.TunnelID]; !ok {
							errOut <- ErrInvalidTunnel
							return
						}

						if len(onion.Tunnels[hdr.TunnelID]) == 0 {
							err = onion.RegisterIncomingConnection(hdr.TunnelID)
							if err != nil {
								errOut <- err
								return
							}
						}

						apiMessage := api.OnionTunnelData{
							TunnelID: tunnel.PrevHopTunnelID,
							Data:     dataMsg.Data,
						}

						err = onion.SendMsgToAPI(tunnel.PrevHopTunnelID, &apiMessage)
						// TODO: figure out if we want to really do nothing here with that error

					case p2p.RelayTypeTunnelExtend: // this be quite interesting
						extendMsg := p2p.RelayTunnelExtend{}
						err = extendMsg.Parse(decryptedRelayMsg)
						if err != nil {
							errOut <- err
							return
						}
						var nextLink *Link
						nextLink, err = onion.GetOrCreateLink(extendMsg.Address, extendMsg.Port)
						if err != nil {
							errOut <- err
							return
						}

						tunnel.NextHopLink = nextLink
						tunnel.NextHopTunnelID = onion.NewTunnelID()
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
						case <-time.After(time.Duration(cfg.CreateTimeout) * time.Second): // timeout
							errOut <- ErrTimedOut
							return
						}

						// TODO: finish implementing
					default:
						err = p2p.ErrInvalidMessage
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
				encryptedMsg, err := p2p.EncryptRelay(data, tunnel.DHShared)
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

func (link *Link) HandleConnection(onion *Onion, cfg *Config, errOut chan error) {
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
			onion.RemoveTunnel(hdr.TunnelID)
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
				onion.RemoveTunnel(hdr.TunnelID)
				continue
			}

			dhShared, tunnelCreated, err := HandleTunnelCreate(msg, cfg)
			if err != nil {
				log.Printf("Error handling tunnel create message: %v", err)
				onion.RemoveTunnel(hdr.TunnelID)
				continue
			}

			if _, ok := onion.Tunnels[hdr.TunnelID]; ok {
				log.Printf("Received tunnel create for existing tunnel id")
				continue
			}
			onion.Tunnels[hdr.TunnelID] = make([]*api.Connection, 0)

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

			// no we start the normal message handling for this tunnel
			go HandleTunnelSegment(&receivingTunnel, onion, cfg, errOut)
		}
	}
}
