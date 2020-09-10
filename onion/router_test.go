package onion

import (
	"crypto/rsa"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"bawang/api"
	"bawang/config"
)

func TestRouter_BuildTunnel(t *testing.T) {
	cfgPeer1 := config.Config{}
	err := cfgPeer1.FromFile("../.testing/bootstrap.conf")
	require.Nil(t, err)
	router1 := NewRouter(&cfgPeer1)

	cfgPeer2 := config.Config{}
	err = cfgPeer2.FromFile("../.testing/peer-2.conf")
	require.Nil(t, err)
	router2 := NewRouter(&cfgPeer2)

	cfgPeer3 := config.Config{}
	err = cfgPeer3.FromFile("../.testing/peer-3.conf")
	require.Nil(t, err)
	router3 := NewRouter(&cfgPeer3)

	cfgPeer4 := config.Config{}
	err = cfgPeer4.FromFile("../.testing/peer-4.conf")
	require.Nil(t, err)
	router4 := NewRouter(&cfgPeer4)

	// now start all listeners
	quitChan := make(chan struct{})
	errChanOnion1 := make(chan error)
	errChanOnion2 := make(chan error)
	errChanOnion3 := make(chan error)
	errChanOnion4 := make(chan error)
	go ListenOnionSocket(&cfgPeer1, router1, errChanOnion1, quitChan)
	go ListenOnionSocket(&cfgPeer2, router2, errChanOnion2, quitChan)
	go ListenOnionSocket(&cfgPeer3, router3, errChanOnion3, quitChan)
	go ListenOnionSocket(&cfgPeer4, router4, errChanOnion4, quitChan)

	time.Sleep(1 * time.Second) // annoyingly wait for the sockets to fully start

	apiConn := &api.Connection{}
	peers := []*Peer{
		{Port: uint16(cfgPeer2.P2PPort), Address: net.ParseIP(cfgPeer2.P2PHostname), HostKey: &rsa.PublicKey{N: cfgPeer2.HostKey.N, E: cfgPeer2.HostKey.E}},
		{Port: uint16(cfgPeer3.P2PPort), Address: net.ParseIP(cfgPeer3.P2PHostname), HostKey: &rsa.PublicKey{N: cfgPeer3.HostKey.N, E: cfgPeer3.HostKey.E}},
		{Port: uint16(cfgPeer4.P2PPort), Address: net.ParseIP(cfgPeer4.P2PHostname), HostKey: &rsa.PublicKey{N: cfgPeer4.HostKey.N, E: cfgPeer4.HostKey.E}},
	}
	tunnel, err := router1.BuildTunnel(peers, apiConn)

	require.Nil(t, err)
	require.NotNil(t, tunnel)

	assert.Equal(t, 3, len(tunnel.Hops))
	assert.NotNil(t, tunnel.Hops[0].DHShared)
	assert.NotNil(t, tunnel.Hops[1].DHShared)
	assert.NotNil(t, tunnel.Hops[2].DHShared)
}
