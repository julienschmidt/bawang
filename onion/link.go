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

	"bawang/p2p"
)

var (
	ErrInvalidTunnel     = errors.New("invalid tunnel")
	ErrTimedOut          = errors.New("timed out")
	ErrAlreadyRegistered = errors.New("a listener is already registered for this tunnel ID")
)

// message is a simple internal struct to combine a p2p.Header with the message body.
type message struct {
	hdr  p2p.Header
	body []byte
}

// Link abstracts TLS level connections between peers which can be reused by multiple tunnels.
type Link struct {
	address net.IP
	port    uint16

	nc net.Conn
	rd *bufio.Reader

	l      sync.Mutex // guards fields below
	msgBuf [p2p.MessageSize]byte

	// data channels for communication with other goroutines
	dataOut map[uint32]chan message // output data channels for received messages with corresponding tunnel IDs
	Quit    chan struct{}
}

// newLink opens a new TLS connection to a peer given by address:port and returns a Link tracking that connection.
func newLink(address net.IP, port uint16) (link *Link, err error) {
	link = &Link{
		address: address,
		port:    port,
		dataOut: make(map[uint32]chan message),
		Quit:    make(chan struct{}),
	}

	err = link.connect()
	if err != nil {
		return nil, err
	}

	return link, nil
}

// newLinkFromExistingConn creates a Link using an existing net.Conn,
// e.g. when creating a new onion Link after receiving an incoming connection.
func newLinkFromExistingConn(conn net.Conn) (link *Link) {
	ip, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		log.Printf("Error parsing client remote ip: %v\n", err)
	}

	portParsed, err := strconv.ParseUint(port, 10, 32)
	if err != nil {
		log.Printf("Error parsing client remote port: %v\n", err)
	}
	return &Link{
		address: net.ParseIP(ip),
		port:    uint16(portParsed),
		nc:      conn,
		rd:      bufio.NewReader(conn),
		dataOut: make(map[uint32]chan message),
		Quit:    make(chan struct{}),
	}
}

// connect initializes a TLS connection to the peer given by Link.address and Link.port
func (link *Link) connect() (err error) {
	tlsConfig := tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // peers do use self-signed certs
	}

	nc, err := tls.Dial("tcp", link.address.String()+":"+strconv.Itoa(int(link.port)), &tlsConfig)
	if err != nil {
		log.Printf("Error opening tls connection to peer: %v", err)
		return
	}

	link.nc = nc
	link.rd = bufio.NewReader(nc)

	return nil
}

// isUnused checks whether this Link is used by any tunnels
func (link *Link) isUnused() (unused bool) {
	return len(link.dataOut) == 0
}

// register registers a message output channel for a tunnel with ID tunnelID with this link
// after registering incoming messages for this tunnel ID will be queued into dataOut
func (link *Link) register(tunnelID uint32, dataOut chan message) (err error) {
	link.l.Lock()
	defer link.l.Unlock()

	_, ok := link.dataOut[tunnelID]
	if ok {
		return ErrAlreadyRegistered
	}

	link.dataOut[tunnelID] = dataOut
	return nil
}

// hasTunnel returns true if there is a tunnel with ID tunnelID registered on this Link
func (link *Link) hasTunnel(tunnelID uint32) (ok bool) {
	link.l.Lock()
	_, ok = link.dataOut[tunnelID]
	link.l.Unlock()

	return
}

// getDataOut returns the dataOut for a given tunnelID, if it exists.
func (link *Link) getDataOut(tunnelID uint32) (dataOut chan message, ok bool) {
	link.l.Lock()
	dataOut, ok = link.dataOut[tunnelID]
	link.l.Unlock()
	return
}

// removeTunnel unregister the tunnel with ID tunnelID from this Link
func (link *Link) removeTunnel(tunnelID uint32) {
	link.l.Lock()
	if dataOut, ok := link.dataOut[tunnelID]; ok {
		close(dataOut)
	}
	delete(link.dataOut, tunnelID)
	link.l.Unlock()
}

// destroy terminates this Link connection by closing all data channels and closing the underlying net.Conn
func (link *Link) destroy() (err error) {
	for _, dataChan := range link.dataOut {
		close(dataChan)
	}
	err = link.nc.Close()
	return
}

// Close stops the goroutine Link handler
func (link *Link) Close() {
	close(link.Quit)
}

// readMsg reads a message from the underlying network connection and returns its type and message body.
func (link *Link) readMsg() (msg message, err error) {
	// read the message header
	var hdr p2p.Header
	if err = hdr.Read(link.rd); err != nil {
		return msg, err
	}

	// ready message body
	link.l.Lock()
	defer link.l.Unlock()
	body := link.msgBuf[:p2p.MaxBodySize]
	_, err = io.ReadFull(link.rd, body)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return msg, err
	}

	return message{hdr, body}, nil
}

// sendRelay sends an onion p2p.Message of type p2p.TypeTunnelRelay on this Link.
// The message body is passed as a packed, raw byte array. Will prepend a correct p2p.Header before the relay message
func (link *Link) sendRelay(tunnelID uint32, msg []byte) (err error) {
	if len(msg) > p2p.MessageSize-p2p.HeaderSize {
		return p2p.ErrInvalidMessage
	}

	header := p2p.Header{
		TunnelID: tunnelID,
		Type:     p2p.TypeTunnelRelay,
	}

	link.l.Lock()

	data := link.msgBuf[:]
	header.Pack(data[:p2p.HeaderSize])
	copy(data[p2p.HeaderSize:], msg)

	_, err = link.nc.Write(data)
	link.l.Unlock()

	return err
}

// sendDestroyTunnel sends a p2p.TunnelDestroy for the given tunnelID on this link
func (link *Link) sendDestroyTunnel(tunnelID uint32) (err error) {
	destroyMsg := p2p.TunnelDestroy{}
	err = link.sendMsg(tunnelID, &destroyMsg)
	return
}

// sendMsg sends a p2p.Message for the given tunnelID on this link. Handles packing of p2p.Header and p2p.Message packing.
func (link *Link) sendMsg(tunnelID uint32, msg p2p.Message) (err error) {
	link.l.Lock()
	defer link.l.Unlock()

	data := link.msgBuf[:]
	n, err := p2p.PackMessage(data, tunnelID, msg)
	if err != nil {
		return err
	}

	data = data[:n]
	_, err = link.nc.Write(data)

	return err
}
