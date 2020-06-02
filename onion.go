package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"time"

	"bawang/message"
	"golang.org/x/crypto/nacl/box"
)

type Circuit struct {
	Peer        net.IP
	PeerHostKey []byte
}

type Peer struct {
	DHShared *[32]byte
	Port     uint16
	Address  net.IP
	HostKey  []byte
	TunnelID uint32
}

func performOnionHandshake(peer *Peer, wr *bufio.Writer, rd *bufio.Reader, conn *tls.Conn) (err error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("Error generating diffie hellman keys: %v", err)
		return
	}
	onionCreate := message.OnionPeerCreate{
		DHPubkey: *pub,
		TunnelID: peer.TunnelID,
	}
	err = message.WriteMessage(wr, &onionCreate)

	err = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		return
	}

	var hdr message.Header
	err = hdr.Read(rd)
	if err != nil {
		if err == io.EOF {
			return
		}
		log.Printf("Error reading message header: %v", err)
		return
	}

	if hdr.Type != message.TypeOnionPeerCreated {
		log.Println("Received invalid onion message from peer")
		err = message.ErrInvalidMessage
		return
	}

	// read message body
	data := make([]byte, hdr.Size)
	_, err = io.ReadFull(rd, data)
	if err != nil {
		log.Printf("Error reading message body: %v", err)
		return
	}

	var onionCreated message.OnionPeerCreated
	err = onionCreated.Parse(data)
	if err != nil {
		log.Printf("Error parsing message body: %v", err)
		return
	}

	peer.DHShared = new([32]byte)
	box.Precompute(peer.DHShared, pub, priv)

	return
}

func buildOnionCircuit(peers [3]Peer, wr *bufio.Writer, rd *bufio.Reader, conn *tls.Conn) (err error) {
	err = performOnionHandshake(&peers[0], wr, rd, conn)
	if err != nil {
		return
	}

	return
}

func openOnionConnection(peers [3]Peer) (err error) {
	tlsConfig := tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", peers[0].Address.String()+":"+strconv.Itoa(int(peers[0].Port)), &tlsConfig)
	if err != nil {
		log.Printf("Error opening tls connection to peer: %v", err)
	}
	defer conn.Close()

	rd := bufio.NewReader(conn)
	wr := bufio.NewWriter(conn)

	err = buildOnionCircuit(peers, wr, rd, conn)

	if err != nil {
		return
	}

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
			log.Println("Onion Tunnel Build")

		case message.TypeOnionPeerExtend:
			var msg message.OnionPeerExtend
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion Tunnel Data")

		case message.TypeOnionPeerRelay:
			var msg message.OnionPeerRelay
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion Tunnel Cover")
		}
	}
}

func listenOnionSocket(cfg *Config) (err error) {
	// construct tls certificate from p2p hostkey
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Voidphone"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, cfg.HostKey.Public(), cfg.HostKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
		return
	}

	privKey := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(cfg.HostKey),
	}

	cert, err := tls.X509KeyPair(derBytes, privKey.Bytes)
	certs := []tls.Certificate{cert}

	tlsConfig := tls.Config{
		Certificates:       certs,
		InsecureSkipVerify: true,
	}
	ln, err := tls.Listen("tcp", cfg.P2PHostname+":"+strconv.Itoa(cfg.P2PPort), &tlsConfig)
	if err != nil {
		return
	}
	defer ln.Close()
	log.Printf("Onion Server Listening at %v:%v", cfg.P2PHostname, cfg.P2PPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// TODO: error on client connection
			log.Println("Error accepting client connection")
			continue
		}
		log.Println("Received new connection")

		go handleOnionConnection(conn)
	}
}
