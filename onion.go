package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"bawang/message"
	"golang.org/x/crypto/nacl/box"
)

var (
	links                map[rsa.PublicKey]*Link
	errAlreadyRegistered = errors.New("there is a listener already registered for this tunnel ID")
	errInvalidCircuit    = errors.New("invalid circuit configuration")
	errTimedOut          = errors.New("timed out")
)

type Link struct {
	cfg         *Config
	Address     net.IP
	Port        uint16
	PeerHostKey *rsa.PublicKey

	l      sync.Mutex // guards fields below
	msgBuf [message.MaxSize]byte
	nc     net.Conn
	rd     *bufio.Reader

	// data channels for communication with other goroutines
	DataOut map[uint32]chan []byte
	Quit    chan int
}

func NewLink(cfg *Config, address net.IP, port uint16, hostKey *rsa.PublicKey) (link *Link, err error) {
	link = &Link{
		cfg:         cfg,
		Address:     address,
		Port:        port,
		PeerHostKey: hostKey,
	}
	// output channels for corresponding tunnel IDs
	link.DataOut = make(map[uint32]chan []byte)
	link.Quit = make(chan int)
	err = link.connect()
	if err != nil {
		return nil, err
	}
	return
}

func (link *Link) connect() (err error) {
	tlsConfig := tls.Config{
		InsecureSkipVerify: true,
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

func (link *Link) registerChannel(tunnelID uint32, c chan []byte) (err error) {
	_, ok := link.DataOut[tunnelID]
	if ok {
		err = errAlreadyRegistered
		return
	}
	link.DataOut[tunnelID] = c
	return
}

func (link *Link) destroy() (err error) {
	link.Quit <- 1
	return
}

func (link *Link) Send(msg message.Message) (err error) {
	data := link.msgBuf[:]
	n, err := message.PackMessage(data, msg)
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

func (link *Link) HandleConnection() (err error) {
	return
}

type Peer struct {
	DHShared *[32]byte
	Port     uint16
	Address  net.IP
	HostKey  *rsa.PublicKey
	TunnelID uint32 // TODO: maybe need to move this to Circuit
}

type Circuit struct {
	ID        uint32
	Hops      []*Peer
	localLink *Link
	linkData  chan []byte
}

func (circuit *Circuit) BuildCircuit(cfg *Config) (err error) {
	if len(circuit.Hops) < 3 {
		log.Printf("Insufficient number of hops in circuit")
		err = errInvalidCircuit
		return
	}

	// TODO: implement more than only the first hop
	firstHop := circuit.Hops[0]
	link, ok := links[*firstHop.HostKey]
	if !ok {
		link, err = NewLink(cfg, firstHop.Address, firstHop.Port, firstHop.HostKey)
		if err != nil {
			log.Printf("Error initializing new link connectio: %v", err)
			return
		}
	}
	circuit.localLink = link

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("Error generating diffie hellman keys: %v", err)
		return
	}
	onionCreate := &message.OnionPeerCreate{
		DHPubkey: *pub,
		TunnelID: firstHop.TunnelID,
	}

	circuit.linkData = make(chan []byte, 10)
	err = link.registerChannel(firstHop.TunnelID, circuit.linkData)
	if err != nil {
		fmt.Printf("Failed to open receive data channel to link: %v", err)
		return
	}
	err = link.Send(onionCreate)
	if err != nil {
		fmt.Printf("Failed to send OnionCreate to peer: %v", err)
		return
	}

	// TODO: deal with terminating channel
	var response []byte
	select {
	case response = <-circuit.linkData:
		break
	case <-time.After(time.Duration(cfg.BuildTimeout) * time.Second):
		err = errTimedOut
		fmt.Printf("Timed out waiting for answer OnionCreated: %v", err)
		return
	}

	var hdr message.Header
	err = hdr.Parse(response)
	if err != nil {
		log.Printf("Error reading message header: %v", err)
		return
	}

	// read message body
	var onionCreated message.OnionPeerCreated
	err = onionCreated.Parse(response[message.HeaderSize:])
	if err != nil {
		log.Printf("Error parsing message body: %v", err)
		return
	}

	firstHop.DHShared = new([32]byte)
	box.Precompute(firstHop.DHShared, &onionCreated.DHPubkey, priv)

	return
}

func handleOnionConnection(conn net.Conn) {
	defer conn.Close()

	var msgBuf [message.MaxSize]byte
	rd := bufio.NewReader(conn)

	for {
		// read the message header
		var hdr message.Header
		err := hdr.Read(rd)
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Printf("Error reading message header: %v", err)
			return
		}

		// ready message body
		data := msgBuf[:hdr.Size]
		_, err = io.ReadFull(rd, data)
		if err != nil {
			log.Printf("Error reading message body: %v", err)
			return
		}

		// handle message
		switch hdr.Type {
		case message.TypeOnionPeerCreate:
			var msg message.OnionPeerCreate
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion TunnelID Build")

		case message.TypeOnionPeerExtend:
			var msg message.OnionPeerExtend
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion TunnelID Data")

		case message.TypeOnionPeerRelay:
			var msg message.OnionPeerRelay
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion TunnelID Cover")
		}
	}
}

func ListenOnionSocket(cfg *Config, errOut chan error, quit chan struct {}) {
	// construct tls certificate from p2p hostkey
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		log.Printf("Failed to generate serial number: %v", err)
		errOut <- err
		return
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Voidphone"},
		},

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, cfg.HostKey.Public(), cfg.HostKey)
	if err != nil {
		log.Printf("Failed to create certificate: %s", err)
		errOut <- err
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(cfg.HostKey)
	if err != nil {
		log.Printf("Failed to create certificate: %s", err)
		errOut <- err
		return
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	cert, err := tls.X509KeyPair(certPem, privPem)
	if err != nil {
		log.Printf("Failed to create server key pair %s", err)
		errOut <- err
		return
	}

	certs := []tls.Certificate{cert}

	tlsConfig := tls.Config{
		Certificates:       certs,
		//InsecureSkipVerify: true,
	}
	ln, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", cfg.P2PHostname, cfg.P2PPort), &tlsConfig)
	if err != nil {
		errOut <- err
		log.Printf("Failed to open tls connection: %s", err)
		return
	}
	defer ln.Close()
	log.Printf("Onion Server Listening at %v:%v", cfg.P2PHostname, cfg.P2PPort)

	for {
		select {
		case <-quit:
			return
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			//errOut <- err
			// TODO: error on client connection
			log.Println("Error accepting client connection")
			continue
		}
		log.Println("Received new connection")

		go handleOnionConnection(conn)
	}
}
