package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestListenOnionSocket(t *testing.T) {
	cfg := Config{
		P2PHostname:     "127.0.0.1",
		P2PPort:         15000,
		RPSAPIAddress:   "127.0.0.1:14001",
		OnionAPIAddress: "127.0.0.1:14000",
		BuildTimeout:    5,
		CreateTimeout:   5,
		APITimeout:      5,
		Verbosity:       2,
	}

	hostKey, err := rsa.GenerateKey(rand.Reader, 4096)
	assert.Nil(t, err)
	cfg.HostKey = hostKey

	errChan := make(chan error)
	quitChan := make(chan struct{})

	go ListenOnionSocket(&cfg, errChan, quitChan)
	time.Sleep(1 * time.Second) // annoyingly wait for the socket to fully start

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", cfg.P2PHostname, cfg.P2PPort), tlsConfig)
	assert.Nil(t, err)
	err = conn.CloseWrite()
	assert.Nil(t, err)

	if conn != nil {
		conn.Close()
		close(quitChan)
	}
}
