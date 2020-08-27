package main

import (
	"bawang/onion"
	"bufio"
	"io"
	"log"
	"net"

	"bawang/api"
)

func handleAPIConnection(conn net.Conn) {
	defer conn.Close()

	var msgBuf [api.MaxSize]byte
	rd := bufio.NewReader(conn)

	for {
		// read the message header
		var hdr api.Header
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
		case api.TypeOnionTunnelBuild:
			var msg api.OnionTunnelBuild
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion TunnelID Build")

		case api.TypeOnionTunnelDestroy:
			var msg api.OnionTunnelDestroy
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion TunnelID Destroy")

		case api.TypeOnionTunnelData:
			var msg api.OnionTunnelData
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion TunnelID Data")

		case api.TypeOnionCover:
			var msg api.OnionCover
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing message body: %v", err)
				continue
			}
			// TODO: some action
			log.Println("Onion TunnelID Cover")

		default:
			log.Println("Invalid message type:", hdr.Type)
		}
	}
}

func listenAPISocket(cfg *onion.Config, errOut chan error, quit chan struct{}) {
	ln, err := net.Listen("tcp", cfg.OnionAPIAddress)
	if err != nil {
		errOut <- err
		return
	}
	defer ln.Close()
	log.Printf("API Server Listening at %v", cfg.OnionAPIAddress)

	for {
		select {
		case <-quit:
			return
		default:
		}

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
