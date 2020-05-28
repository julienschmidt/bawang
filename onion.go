package main

import (
	"bawang/message"
	"bufio"
	"io"
	"log"
	"net"
)

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

func listenOnionSocket(cfg *Config) error {
	ln, err := net.Listen("tcp", cfg.P2PHostname+":"+string(cfg.P2PPort))
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

		go handleOnionConnection(conn)
	}
}
