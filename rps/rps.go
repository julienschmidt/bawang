package rps

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"bawang/api"
	"bawang/config"
)

var (
	errInvalidPeer = errors.New("invalid peer")
)

type Peer struct {
	DHShared [32]byte
	Port     uint16
	Address  net.IP
	HostKey  *rsa.PublicKey
}

type RPS interface {
	GetPeer() (peer *Peer, err error)
	SampleIntermediatePeers(n int, target *Peer) (peers []*Peer, err error)
	Close()
}

type rps struct {
	cfg *config.Config

	l      sync.Mutex // guards fields below
	msgBuf [api.MaxSize]byte
	nc     net.Conn
	rd     *bufio.Reader
}

func New(cfg *config.Config) (RPS, error) {
	if cfg == nil {
		return nil, errors.New("invalid config")
	}

	r := &rps{
		cfg: cfg,
	}
	if err := r.connect(); err != nil {
		return nil, err
	}
	return r, nil
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
	err := r.nc.Close()
	if err != nil {
		log.Printf("error closing RPS API connection %s", err)
	}
}

func (r *rps) GetPeer() (peer *Peer, err error) {
	// concurrent IO not such a great idea
	r.l.Lock()
	defer r.l.Unlock()

	// send query
	var query api.RPSQuery
	data := r.msgBuf[:]
	n, err := api.PackMessage(data, &query)
	if err != nil {
		return nil, err
	}

	data = data[:n]
	_, err = r.nc.Write(data)
	if err != nil {
		return nil, err
	}

	// read reply
	replyDeadline := time.Now().Add(time.Duration(r.cfg.APITimeout) * time.Second)
	err = r.nc.SetReadDeadline(replyDeadline)
	if err != nil {
		return nil, err
	}

	var hdr api.Header
	err = hdr.Read(r.rd)
	if err != nil || hdr.Type != api.TypeRPSPeer {
		log.Print("invalid or no message received from rps module")
		return nil, api.ErrInvalidMessage
	}

	var reply api.RPSPeer
	data = r.msgBuf[:hdr.Size]
	_, err = io.ReadFull(r.rd, data)
	if err != nil {
		log.Printf("Error reading message body: %v", err)
		return nil, err
	}

	err = reply.Parse(data)
	if err != nil {
		log.Printf("Error parsing message body: %v", err)
		return nil, err
	}

	port := reply.PortMap.Get(api.AppTypeOnion)
	if port == 0 { // no Onion port
		return nil, errInvalidPeer
	}

	peer = &Peer{
		Address: reply.Address,
		Port:    port,
	}
	peer.HostKey, err = x509.ParsePKCS1PublicKey(reply.DestHostKey)
	if err != nil {
		log.Printf("Received peer with invalid host key from rps module: %v", err)
		return nil, err
	}

	return peer, nil
}

func (r *rps) SampleIntermediatePeers(n int, target *Peer) (peers []*Peer, err error) {
	if n < 2 {
		return nil, errors.New("invalid number of hops")
	}

	peers = make([]*Peer, n)
	for i := 0; i < n-1; i++ {
		peers[i], err = r.GetPeer()
		if err != nil {
			return nil, err
		}
	}
	peers[n-1] = target
	return peers, nil
}
