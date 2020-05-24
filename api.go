package main

import (
	"bufio"
	"io"
	"log"
	"net"
)

func handleAPIConnection(conn net.Conn) {
	defer conn.Close()

	var msgBuf [msgMaxSize]byte
	rd := bufio.NewReader(conn)

	for {
		// read the message header
		hdr, err := readMsgHeader(rd)
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
		case msgTypeOnionTunnelBuild:
			var msg msgOnionTunnelBuild
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion Tunnel Build")

		case msgTypeOnionTunnelDestroy:
			var msg msgOnionTunnelDestroy
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion Tunnel Destroy")

		case msgTypeOnionTunnelData:
			var msg msgOnionTunnelData
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion Tunnel Data")

		case msgTypeOnionCover:
			var msg msgOnionCover
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
