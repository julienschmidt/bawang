package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"time"

	"bawang/message"
)

func getRandomPeer(cfg *Config) (peer message.RPSPeer, err error) {
	conn, err := net.Dial("tcp", cfg.RPSAPIAddress)
	if err != nil {
		return
	}
	defer conn.Close()

	msg := new(message.RPSQuery)
	buf := make([]byte, msg.PackedSize()+message.HeaderSize)
	_, err = message.PackMessage(buf, msg)

	_, err = conn.Write(buf)

	rd := bufio.NewReader(conn)
	hdr := new(message.Header)
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(cfg.APITimeout) * time.Second))
	if err != nil {
		return
	}

	err = hdr.Read(rd)

	if err != nil || hdr.Type != message.TypeRPSPeer {
		log.Print("invalid or no message received from rps module")
		err = message.ErrInvalidMessage
		return
	}

	// ready message body
	data := make([]byte, hdr.Size)
	_, err = io.ReadFull(rd, data)
	if err != nil {
		log.Printf("Error reading message body: %v", err)
		return
	}

	err = peer.Parse(data)
	if err != nil {
		log.Printf("Error parsing message body: %v", err)
		return
	}
	return
}

func handleAPIConnection(conn net.Conn) {
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
		case message.TypeOnionTunnelBuild:
			var msg message.OnionTunnelBuild
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion Tunnel Build")

		case message.TypeOnionTunnelDestroy:
			var msg message.OnionTunnelDestroy
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion Tunnel Destroy")

		case message.TypeOnionTunnelData:
			var msg message.OnionTunnelData
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion Tunnel Data")

		case message.TypeOnionCover:
			var msg message.OnionCover
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

func listenAPISocket(cfg *Config) error {
	ln, err := net.Listen("tcp", cfg.OnionAPIAddress)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// TODO: error on client connection
			log.Println("Error accepting client connection")
			continue
		}
		log.Println("Received new connection")

		go handleAPIConnection(conn)
	}
}
