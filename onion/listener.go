package onion

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"strconv"

	"bawang/config"
)

// ListenOnionSocket opens a tls listener on the host specified in cfg that handles incoming p2p onion traffic.
func ListenOnionSocket(cfg *config.Config, router *Router, errOut chan error, quit chan struct{}) {
	cert, err := tlsCertFromHostKey(cfg.HostKey)
	if err != nil {
		errOut <- err
		return
	}

	tlsConfig := tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, //nolint:gosec // peers do use self-signed certs
	}
	ln, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", cfg.P2PHostname, cfg.P2PPort), &tlsConfig)
	if err != nil {
		errOut <- err
		log.Printf("Failed to open TLS connection: %v\n", err)
		return
	}
	defer ln.Close()
	log.Printf("Onion Server Listening at %v:%v\n", cfg.P2PHostname, cfg.P2PPort)

	goRoutineErrOut := make(chan error, 10)
	for {
		select {
		case <-quit:
			return
		case goRoutineErr := <-goRoutineErrOut:
			log.Printf("Error in goroutine: %v\n", goRoutineErr)
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			// TODO: error on client connection
			log.Printf("Error accepting client connection: %v\n", err)
			continue
		}
		defer conn.Close()

		ip, port, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			log.Printf("Error parsing client remote ip: %v\n", err)
			continue
		}

		portParsed, err := strconv.ParseUint(port, 10, 32)
		if err != nil {
			log.Printf("Error parsing client remote port: %v\n", err)
			continue
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			log.Printf("Invalid TLS connection from peer %v:%v\n", ip, port)
			continue
		}

		log.Printf("Received new connection from peer %v:%v\n", ip, port)

		_, err = router.CreateLinkFromExistingConn(tlsConn)
		if err != nil {
			log.Printf("Error creating link to %v:%v: %v\n", ip, portParsed, err)
			continue
		}
	}
}

// tlsCertFromHostKey creates a tls.Certificate from a given rsa.PrivateKey usable in tls.Listen or tls.Dial
func tlsCertFromHostKey(hostKey *rsa.PrivateKey) (cert tls.Certificate, err error) {
	// construct tls certificate from p2p hostkey
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Printf("Failed to generate serial number: %v\n", err)
		return cert, err
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

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, hostKey.Public(), hostKey)
	if err != nil {
		log.Printf("Failed to create certificate: %v\n", err)
		return cert, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(hostKey)
	if err != nil {
		log.Printf("Failed to create certificate: %v\n", err)
		return cert, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	cert, err = tls.X509KeyPair(certPem, privPem)
	if err != nil {
		log.Printf("Failed to create server key pair: %v\n", err)
		return cert, err
	}
	return cert, nil
}
