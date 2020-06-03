package main

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"bawang/message"
)

type Peer struct {
	DHShared *[32]byte
	Port     uint16
	Address  net.IP
	HostKey  []byte
	TunnelID uint32
}

var (
	errInvalidPeer = errors.New("invalid peer")
)

type rps struct {
	cfg *Config

	l      sync.Mutex // guards fields below
	msgBuf [message.MaxSize]byte
	nc     net.Conn
	rd     *bufio.Reader
}

func NewRPS(cfg *Config) (r *rps, err error) {
	r = &rps{
		cfg: cfg,
	}
	err = r.connect()
	if err != nil {
		return nil, err
	}
	return
}

func (r *rps) connect() (err error) {
	r.nc, err = net.Dial("tcp", r.cfg.RPSAPIAddress)
	if err != nil {
		return err
	}
	r.rd = bufio.NewReader(r.nc)
	return
}

func (r *rps) Close() {
	r.nc.Close()
}

func (r *rps) getPeer() (peer Peer, err error) {
	// concurrent IO not such a great idea
	r.l.Lock()
	defer r.l.Unlock()

	// send query
	var query message.RPSQuery
	data := r.msgBuf[:]
	n, err := message.PackMessage(data, &query)
	if err != nil {
		return
	}

	data = data[:n]
	_, err = r.nc.Write(data)
	if err != nil {
		return
	}

	// read reply
	replyDeadline := time.Now().Add(time.Duration(r.cfg.APITimeout) * time.Second)
	err = r.nc.SetReadDeadline(replyDeadline)
	if err != nil {
		return
	}

	var hdr message.Header
	err = hdr.Read(r.rd)
	if err != nil || hdr.Type != message.TypeRPSPeer {
		log.Print("invalid or no message received from rps module")
		err = message.ErrInvalidMessage
		return
	}

	var reply message.RPSPeer
	data = r.msgBuf[:hdr.Size]
	_, err = io.ReadFull(r.rd, data)
	if err != nil {
		log.Printf("Error reading message body: %v", err)
		return
	}

	err = reply.Parse(data)
	if err != nil {
		log.Printf("Error parsing message body: %v", err)
		return
	}

	port := reply.PortMap.Get(message.AppTypeOnion)
	if port == 0 { // no Onion port
		err = errInvalidPeer
		return
	}

	peer.Address = reply.Address
	peer.Port = port
	peer.HostKey = reply.DestHostKey // TODO: verify

	return
}
