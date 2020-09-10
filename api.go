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

func HandleAPIConnection(cfg *config.Config, apiConn *api.Connection, rps RPSInterface, router *onion.Router) {
	defer func() {
		router.RemoveAPIConnection(apiConn)
		err := apiConn.Terminate()
		if err != nil {
			log.Printf("Error terminating API conn: %v\n", err)
			return
		}
	}()

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

			var peers []*onion.Peer
			for i := 0; i < cfg.TunnelLength-1; i++ {
				var peer *onion.Peer
				peer, err = rps.GetPeer()
				if err != nil {
					log.Printf("Error getting random peer: %v\n", err)
					err = apiConn.SendError(api.TypeOnionTunnelBuild, 0)
					if err != nil {
						log.Printf("Error sending error: %v\n", err)
						return
					}
				}
				peers = append(peers, peer)
			}

			targetKey, err := msg.ParseHostKey()
			if err != nil {
				log.Printf("Error parsing host key: %v\n", err)
				return
			}

			targetPeer := &onion.Peer{
				Port:    msg.OnionPort,
				Address: msg.Address,
				HostKey: targetKey,
			}

			peers = append(peers, targetPeer)

			tunnel, err := router.BuildTunnel(peers, apiConn)
			if err != nil {
				log.Printf("Error building tunnel: %v\n", err)
				return
			}

			tunnelCreated := api.OnionTunnelReady{
				TunnelID:    tunnel.ID,
				DestHostKey: msg.DestHostKey,
			}

			err = apiConn.Send(&tunnelCreated)
			if err != nil {
				err = apiConn.SendError(api.TypeOnionTunnelBuild, tunnel.ID)
				if err != nil {
					return
				}
			}
			log.Println("Onion TunnelID Build")

		case api.TypeOnionTunnelDestroy:
			var msg api.OnionTunnelDestroy
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing OnionTunnelDestroy message body: %v\n", err)
				return
			}
			router.RemoveAPIConnectionFromTunnel(msg.TunnelID, apiConn)
			log.Printf("Destroying Onion tunnel with ID: %v\n", msg.TunnelID)

		case api.TypeOnionTunnelData:
			var msg api.OnionTunnelData
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing OnionTunnelData message body: %v\n", err)
				return
			}
			err = router.SendData(msg.TunnelID, msg.Data)
			log.Printf("Sending Data on Onion tunnel %v\n", msg.TunnelID)
			if err != nil {
				log.Printf("Error sending onion data on tunnel %v\n", msg.TunnelID)
				err = apiConn.SendError(api.TypeOnionTunnelData, msg.TunnelID)
				if err != nil {
					return
				}
			}

		case api.TypeOnionCover:
			var msg api.OnionCover
			err := msg.Parse(data)
			if err != nil {
				log.Printf("Error parsing OnionCover message body: %v\n", err)
				return
			}
			err = router.SendCover(msg.CoverSize)
			if err != nil {
				log.Println("Error when sending cover traffic")
				_ = apiConn.SendError(api.TypeOnionCover, 0)
				return
			}
			log.Println("Onion TunnelID Cover")

		default:
			log.Println("Invalid message type:", hdr.Type)
		}
	}
}

func ListenAPISocket(cfg *config.Config, router *onion.Router, rps RPSInterface, errOut chan error, quit chan struct{}) {
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
		router.RegisterAPIConnection(&apiConn)

		go HandleAPIConnection(cfg, &apiConn, rps, router)
	}
}
