package main

import (
	"crypto/rsa"
	"io"
	"log"
	"net"

	"bawang/api"
	"bawang/config"
	"bawang/onion"
	"bawang/rps"
)

type Peer = rps.Peer

func HandleAPIConnection(cfg *config.Config, conn *api.Connection, rps rps.RPS, router *onion.Router) {
	defer func() {
		err := router.RemoveAPIConnection(conn)
		if err != nil {
			log.Printf("Error terminating API conn: %v\n", err)
		}
		err = conn.Terminate()
		if err != nil {
			log.Printf("Error terminating API conn: %v\n", err)
		}
	}()

	for {
		// read message from API conn
		apiMsg, err := conn.ReadMsg()
		if err != nil {
			if err == io.EOF {
				// connection closed cleanly
				return
			}
			log.Printf("Error reading message: %v\n", err)
			return
		}

		// handle message
		switch msg := apiMsg.(type) {
		case *api.OnionTunnelBuild:
			var targetKey *rsa.PublicKey
			targetKey, err = msg.ParseHostKey()
			if err != nil {
				log.Printf("Error parsing host key: %v\n", err)
				return
			}

			targetPeer := &Peer{
				Port:    msg.OnionPort,
				Address: msg.Address,
				HostKey: targetKey,
			}

			// sample intermediate peers
			var peers []*Peer
			peers, err = rps.SampleIntermediatePeers(cfg.TunnelLength, targetPeer)
			if err != nil {
				log.Printf("Error getting random peer: %v\n", err)
				err = conn.SendError(0, api.TypeOnionTunnelBuild)
				if err != nil {
					log.Printf("Error sending error: %v\n", err)
					return
				}
			}

			// instruct onion router to build tunnel with given peers
			var tunnel *onion.Tunnel
			tunnel, err = router.BuildTunnel(peers, conn)
			if err != nil {
				log.Printf("Error building tunnel: %v\n", err)
				return
			}

			// send confirmation
			err = conn.Send(&api.OnionTunnelReady{
				TunnelID:    tunnel.ID(),
				DestHostKey: msg.DestHostKey,
			})
			if err != nil {
				err = conn.SendError(tunnel.ID(), api.TypeOnionTunnelBuild)
				if err != nil {
					return
				}
			}
			log.Println("Onion TunnelID Build")

		case *api.OnionTunnelDestroy:
			log.Printf("Destroying Onion tunnel with ID: %v\n", msg.TunnelID)
			err = router.RemoveAPIConnectionFromTunnel(msg.TunnelID, conn)
			if err != nil {
				log.Printf("Error destrying Onion tunnel with ID: %v\n", msg.TunnelID)
				err = conn.SendError(msg.TunnelID, api.TypeOnionTunnelDestroy)
				if err != nil {
					return
				}
			}

		case *api.OnionTunnelData:
			err = router.SendData(msg.TunnelID, msg.Data)
			log.Printf("Sending Data on Onion tunnel %v\n", msg.TunnelID)
			if err != nil {
				log.Printf("Error sending onion data on tunnel %v\n", msg.TunnelID)
				err = conn.SendError(msg.TunnelID, api.TypeOnionTunnelData)
				if err != nil {
					return
				}
			}

		case *api.OnionCover:
			err = router.SendCover(msg.CoverSize)
			if err != nil {
				log.Println("Error when sending cover traffic")
				_ = conn.SendError(0, api.TypeOnionCover)
				return
			}
			log.Println("Onion TunnelID Cover")

		default:
			log.Println("Invalid message type:", apiMsg.Type())
		}
	}
}

func ListenAPISocket(cfg *config.Config, router *onion.Router, rps rps.RPS, errOut chan error, quit chan struct{}) {
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
			log.Printf("Error accepting client connection: %v\n", err)
			continue
		}
		log.Println("Received new connection")

		apiConn := api.NewConnection(conn)
		router.RegisterAPIConnection(apiConn)

		go HandleAPIConnection(cfg, apiConn, rps, router)
	}
}
