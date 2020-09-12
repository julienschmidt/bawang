package onion

import (
	"bufio"
	"crypto/tls"
	"errors"
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

type message struct {
	hdr  p2p.Header
	body []byte
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

func newLink(address net.IP, port uint16) (link *Link, err error) {
	link = &Link{
		Address: address,
		Port:    port,
		dataOut: make(map[uint32]chan message),
		Quit:    make(chan struct{}),
	}

	err = link.connect()
	if err != nil {
		return nil, err
	}

	return link, nil
}

func newLinkFromExistingConn(address net.IP, port uint16, conn net.Conn) (link *Link) {
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

func (link *Link) hasTunnel(tunnelID uint32) (ok bool) {
	_, ok = link.dataOut[tunnelID]

	return
}

func (link *Link) removeTunnel(tunnelID uint32) {
	if _, ok := link.dataOut[tunnelID]; ok {
		close(link.dataOut[tunnelID])
	}
	delete(link.dataOut, tunnelID)
	// TODO: if there are no more listeners on this link we shut it down
}

func (link *Link) destroy() (err error) {
	close(link.Quit)
	err = link.nc.Close()
	return
}

func (link *Link) sendRelay(tunnelID uint32, msg []byte) (err error) {
	if len(msg) > p2p.MaxSize-p2p.HeaderSize {
		return p2p.ErrInvalidMessage
	}

	data := link.msgBuf[:]
	header := p2p.Header{
		TunnelID: tunnelID,
		Type:     p2p.TypeTunnelRelay,
	}
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

func (link *Link) sendDestroyTunnel(tunnelID uint32) (err error) {
	destroyMsg := p2p.TunnelDestroy{}
	err = link.Send(tunnelID, &destroyMsg)
	return
}
