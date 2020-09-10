package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"bawang/config"
	"bawang/onion"
	"bawang/p2p"
)

func TestListenOnionSocket(t *testing.T) {
	cfg := config.Config{
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
	require.Nil(t, err)
	cfg.HostKey = hostKey
	router := onion.NewRouter(&cfg)

	errChan := make(chan error)
	quitChan := make(chan struct{})

	go ListenOnionSocket(&cfg, router, errChan, quitChan)
	time.Sleep(1 * time.Second) // annoyingly wait for the socket to fully start

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // no valid cert for this test
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", cfg.P2PHostname, cfg.P2PPort), tlsConfig)
	require.Nil(t, err)
	require.NotNil(t, conn)

	createMsg := p2p.TunnelCreate{
		Version:     1,
		EncDHPubKey: [32]byte{},
	}
	buf := make([]byte, p2p.MaxSize)
	n, err := p2p.PackMessage(buf, 123, &createMsg)
	require.Nil(t, err)
	n, err = conn.Write(buf[:n])
	require.Nil(t, err)
	assert.Equal(t, createMsg.PackedSize()+p2p.HeaderSize, n)
	err = conn.CloseWrite()
	require.Nil(t, err)

	conn.Close()
	close(quitChan)
}
