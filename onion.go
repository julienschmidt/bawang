package main

import (
	"bawang/onion"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"strconv"
)

func ListenOnionSocket(onjon *onion.Onion, cfg *onion.Config, errOut chan error, quit chan struct{}) {
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
		IsCA:                  true,
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
		Certificates: certs,
		InsecureSkipVerify: true,
	}
	ln, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", cfg.P2PHostname, cfg.P2PPort), &tlsConfig)
	if err != nil {
		errOut <- err
		log.Printf("Failed to open tls connection: %s", err)
		return
	}
	defer ln.Close()
	log.Printf("Onion Server Listening at %v:%v", cfg.P2PHostname, cfg.P2PPort)

	goRoutineErrOut := make(chan error, 10)

	for {
		select {
		case <-quit:
			return
		case goRoutineErr := <- goRoutineErrOut:
			log.Printf("Error in goroutine: %v", goRoutineErr)
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			//errOut <- err
			// TODO: error on client connection
			log.Println("Error accepting client connection")
			continue
		}
		defer conn.Close()

		ip, port, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			log.Println("Error parsing client remote ip")
			continue
		}

		portParsed, err := strconv.ParseUint(port, 10, 32)
		if err != nil {
			log.Println("Error parsing client remote port")
			continue
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			log.Printf("Invalid tls connection from peer %v:%v", ip, port)
			continue
		}

		log.Printf("Received new connection from peer %v:%v", ip, port)

		link := onion.NewLinkFromExistingConn(net.ParseIP(ip), uint16(portParsed), tlsConn)
		onjon.Links = append(onjon.Links, link)
		go link.HandleConnection(onjon, cfg, goRoutineErrOut)
	}
}
