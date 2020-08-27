package onion

import (
	"bawang/p2p"
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"
)

var (
	ErrInvalidTunnel     = errors.New("invalid tunnel configuration")
	ErrTimedOut          = errors.New("timed out")
	ErrAlreadyRegistered = errors.New("a listener is already registered for this tunnel ID")
)

type message struct {
	hdr     p2p.Header
	payload []byte
}

type Onion struct {
	Links     []*Link
	TunnelIDs []uint32
}

func (onion *Onion) NewTunnelID() (tunnelID uint32) {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	tunnelID = random.Uint32()
	isUnique := true
	for {
		for _, id := range onion.TunnelIDs {
			isUnique = isUnique && id == tunnelID
		}

		if isUnique {
			break
		}

		tunnelID = rand.Uint32()
		isUnique = true
	}

	onion.TunnelIDs = append(onion.TunnelIDs, tunnelID)

	return
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
	return
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
	return
}

func NewLinkFromExistingConn(address net.IP, port uint16, conn net.Conn) (link *Link) {
	link = &Link{
		Address: address,
		Port:    port,
		nc:      conn,
		rd:      bufio.NewReader(conn),
		dataOut: make(map[uint32]chan message),
		Quit:    make(chan struct{}),
	}
	defer link.nc.Close()

	return
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

	return
}

func (link *Link) register(tunnelID uint32, dataOut chan message) (err error) {
	_, ok := link.dataOut[tunnelID]
	if ok {
		err = ErrAlreadyRegistered
		return
	}

	link.dataOut[tunnelID] = dataOut
	return
}

func (link *Link) unregister(tunnelID uint32) {
	delete(link.dataOut, tunnelID)
	return
}

func (link *Link) Destroy() (err error) {
	close(link.Quit)
	return
}

func (link *Link) DestroyTunnel(tunnelID uint32) (err error) {
	destroyMsg := p2p.TunnelDestroy{}
	err = link.Send(tunnelID, &destroyMsg)
	return
}

func (link *Link) SendRaw(tunnelID uint32, msgType p2p.Type, msg []byte) (err error) {
	if len(msg) > p2p.MaxSize-p2p.HeaderSize {
		err = p2p.ErrInvalidMessage
		return
	}
	data := link.msgBuf[:]
	header := p2p.Header{TunnelID: tunnelID, Type: msgType}
	header.Pack(data[:p2p.HeaderSize])
	copy(data[p2p.HeaderSize:len(msg)+p2p.HeaderSize], msg)

	link.l.Lock()
	_, err = link.nc.Write(data)
	link.l.Unlock()
	if err != nil {
		return
	}
	return
}

func (link *Link) Send(tunnelID uint32, msg p2p.Message) (err error) {
	data := link.msgBuf[:]
	n, err := p2p.PackMessage(data, tunnelID, msg)
	if err != nil {
		return
	}

	data = data[:n]
	link.l.Lock()
	_, err = link.nc.Write(data)
	link.l.Unlock()
	if err != nil {
		return
	}

	return
}

func (link *Link) HandleOutgoingTunnel(tunnel *Tunnel, onion *Onion, cfg *Config, errOut chan error) {
	// This is the handler go routine for outgoing tunnels that we initiated.
	// It is assumed that the handshake with the peers is completed and the tunnel is fully initiated at this point!
	dataOut := make(chan message, 5) // TODO: determine buffer size
	err := link.register(tunnel.ID, dataOut)
	if err != nil {
		errOut <- err
		return
	}
	defer link.DestroyTunnel(tunnel.ID)
	defer link.unregister(tunnel.ID)

	for {
		select {
		case msg := <-dataOut:
			hdr := msg.hdr
			data := msg.payload
			switch hdr.Type {
			case p2p.TypeTunnelRelay: // TODO: reverse decrypt using all hop shared keys
				decryptedRelayMsg := data
				for i, hop := range tunnel.Hops {
					ok, decryptedRelayMsg, err := p2p.DecryptRelay(decryptedRelayMsg, hop.DHShared)
					if err != nil { // error when decrypting
						errOut <- err
						return
					}

					if ok { // message is meant for us from a hop
						relayHdr := p2p.RelayHeader{}
						err = relayHdr.Parse(decryptedRelayMsg)
						if err != nil {
							return
						}

						switch relayHdr.RelayType {
						case p2p.RelayTypeTunnelData: // TODO: do something with the data message
						default:
							err = p2p.ErrInvalidMessage
							return
						}
					} else if i == len(tunnel.Hops) { // we could not decrypt the message and have removed all layers of encryption
						errOut <- p2p.ErrInvalidMessage
						return
					}
				}
			case p2p.TypeTunnelDestroy: // TODO: implement
			default: // since we assume the circuit to be fully built we cannot accept any other message
				errOut <- p2p.ErrInvalidMessage
				return
			}
		case <-link.Quit:
			return
		}
	}
}

func (link *Link) HandleTunnelSegment(tunnel *TunnelSegment, onion *Onion, cfg *Config, errOut chan error) {
	// This is the handler go routine for incoming tunnels that either are terminated by us or where we are just
	// an in-between hop. The handshake of the previous hop to us is assumed to be done we can, however, receive
	// TunnelExtend commands.
	dataChanPrevHop := make(chan message, 5) // TODO: determine buffer size
	dataChanNextHop := make(chan message, 5)
	err := link.register(tunnel.PrevHopTunnelID, dataChanPrevHop)
	if err != nil {
		errOut <- err
		return
	}
	defer link.DestroyTunnel(tunnel.PrevHopTunnelID)
	defer link.unregister(tunnel.PrevHopTunnelID)

	for {
		select {
		case msg := <-dataChanPrevHop: // we receive a message from the previous hop
			hdr := msg.hdr
			data := msg.payload
			switch hdr.Type {
			case p2p.TypeTunnelRelay:
				ok, decryptedRelayMsg, err := p2p.DecryptRelay(data, tunnel.DHShared)
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
					case p2p.RelayTypeTunnelData: // TODO: do something with the data message
					case p2p.RelayTypeTunnelExtend: // this be quite interesting
						extendMsg := p2p.RelayTunnelExtend{}
						err = extendMsg.Parse(decryptedRelayMsg)
						if err != nil {
							errOut <- err
							return
						}
						nextLink, err := onion.GetOrCreateLink(extendMsg.Address, extendMsg.Port)
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
							n, err := extendedMsg.Pack(packedExtended)
							if err != nil {
								errOut <- err
								return
							}

							encryptedExtended, err := p2p.EncryptRelay(packedExtended[:n], tunnel.DHShared)
							if err != nil {
								errOut <- err
								return
							}
							err = link.SendRaw(tunnel.PrevHopTunnelID, p2p.TypeTunnelRelay, encryptedExtended)
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
				} else {                           // relay message is not meant for us
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

				return
			case p2p.TypeTunnelDestroy: // TODO: implement
			default: // any other message is illegal here
				errOut <- p2p.ErrInvalidMessage
				return
			}
		case msg := <-dataChanNextHop: // we receive a message from the next hop
			hdr := msg.hdr
			//data := msg.payload
			switch hdr.Type {
			case p2p.TypeTunnelRelay: // TODO: implement
			case p2p.TypeTunnelDestroy: // TODO: implement
			default: // any other message is illegal here
				errOut <- p2p.ErrInvalidMessage
				return
			}
		case <-link.Quit:
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
		if err != nil { // TODO: should we terminate on an invalid message here? closes all tunnels on this link
			errOut <- err
			log.Printf("Error reading message body: %v", err)
			return
		}

		_, ok := link.dataOut[hdr.TunnelID]
		if ok {
			link.dataOut[hdr.TunnelID] <- message{hdr, data}
		} else {                                  // we receive the first message on this link for a tunnel we do not know yet
			if hdr.Type != p2p.TypeTunnelCreate { // the first message for a new tunnel MUST be Tunnel Create
				errOut <- p2p.ErrInvalidMessage
				return
			}
			msg := p2p.TunnelCreate{}
			err = msg.Parse(data)
			if err != nil {
				errOut <- err
				log.Printf("Error parsing tunnel create message: %v", err)
				return
			}

			dhShared, tunnelCreated, err := HandleTunnelCreate(msg, cfg)
			if err != nil {
				errOut <- err
				log.Printf("Error handling tunnel create message: %v", err)
				return
			}
			receivingTunnel := TunnelSegment{
				PrevHopTunnelID: hdr.TunnelID,
				DHShared:        dhShared,
			}
			err = link.Send(hdr.TunnelID, &tunnelCreated)
			if err != nil {
				errOut <- err
				log.Printf("Error sending tunnel created message: %v", err)
				return
			}

			// no we start the normal message handling for this tunnel
			go link.HandleTunnelSegment(&receivingTunnel, onion, cfg, errOut)
		}
	}
}
