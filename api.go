package main

import (
	"bufio"
	"io"
	"log"
	"net"

	"bawang/api"
	"bawang/config"
	"bawang/onion"
)

func HandleAPIConnection(apiConn *api.Connection, router *onion.Router, rps *RPS) {
	defer apiConn.Conn.Close()

	var msgBuf [api.MaxSize]byte
	rd := bufio.NewReader(apiConn.Conn)

	for {
		// read the message header
		var hdr api.Header
		err := hdr.Read(rd)
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Printf("Error reading message header: %v\n", err)
			return
		}

		// ready message body
		data := msgBuf[:hdr.Size]
		_, err = io.ReadFull(rd, data)
		if err != nil {
			log.Printf("Error reading message body: %v\n", err)
			return
		}

		// handle message
		switch hdr.Type {
		case api.TypeOnionTunnelBuild:
			var msg api.OnionTunnelBuild
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing OnionTunnelBuild message body: %v\n", err)
				continue
			}
			// TODO: some action
			log.Println("Onion TunnelID Build")

		case api.TypeOnionTunnelDestroy:
			var msg api.OnionTunnelDestroy
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing OnionTunnelDestroy message body: %v\n", err)
				continue
			}
			// TODO: some action
			log.Println("Onion TunnelID Destroy")

		case api.TypeOnionTunnelData:
			var msg api.OnionTunnelData
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing OnionTunnelData message body: %v\n", err)
				continue
			}
			// TODO: some action
			log.Println("Onion TunnelID Data")

		case api.TypeOnionCover:
			var msg api.OnionCover
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing OnionCover message body: %v\n", err)
				continue
			}
			// TODO: some action
			log.Println("Onion TunnelID Cover")

		default:
			log.Println("Invalid message type:", hdr.Type)
		}
	}
}

func ListenAPISocket(cfg *config.Config, router *onion.Router, rps *RPS, errOut chan error, quit chan struct{}) {
	ln, err := net.Listen("tcp", cfg.OnionAPIAddress)
	if err != nil {
		errOut <- err
		return
	}
	defer ln.Close()
	log.Printf("API Server Listening at %v\n", cfg.OnionAPIAddress)

	for {
		select {
		case <-quit:
			return
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			// TODO: error on client connection
			log.Printf("Error accepting client connection: %v\n", err)
			continue
		}
		log.Println("Received new connection")

		apiConn := api.Connection{
			Conn: conn,
		}

		go HandleAPIConnection(&apiConn, router, rps)
	}
}
