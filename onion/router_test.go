package onion

import (
	"bufio"
	"crypto/rsa"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"bawang/api"
	"bawang/config"
	"bawang/rps"
)

func TestRouterBuildTunnel(t *testing.T) {
	cfgPeer1 := config.Config{}
	err := cfgPeer1.FromFile("../.testing/bootstrap.conf")
	require.Nil(t, err)
	apiServer1, apiClient1 := net.Pipe()
	apiConn1 := api.NewConnection(apiServer1)
	router1 := NewRouter(&cfgPeer1)
	router1.apiConnections = []*api.Connection{apiConn1}

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
	apiServer4, apiClient4 := net.Pipe()
	apiConn4 := api.NewConnection(apiServer4)
	router4 := NewRouter(&cfgPeer4)
	router4.apiConnections = []*api.Connection{apiConn4}

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

	peers := []*rps.Peer{
		{Port: uint16(cfgPeer2.P2PPort), Address: net.ParseIP(cfgPeer2.P2PHostname), HostKey: &rsa.PublicKey{N: cfgPeer2.HostKey.N, E: cfgPeer2.HostKey.E}},
		{Port: uint16(cfgPeer3.P2PPort), Address: net.ParseIP(cfgPeer3.P2PHostname), HostKey: &rsa.PublicKey{N: cfgPeer3.HostKey.N, E: cfgPeer3.HostKey.E}},
		{Port: uint16(cfgPeer4.P2PPort), Address: net.ParseIP(cfgPeer4.P2PHostname), HostKey: &rsa.PublicKey{N: cfgPeer4.HostKey.N, E: cfgPeer4.HostKey.E}},
	}
	tunnel, err := router1.BuildTunnel(peers, apiConn1)

	require.Nil(t, err)
	require.NotNil(t, tunnel)

	assert.Equal(t, len(peers), len(tunnel.hops))
	assert.NotNil(t, tunnel.hops[0].DHShared)
	assert.NotNil(t, tunnel.hops[1].DHShared)
	assert.NotNil(t, tunnel.hops[2].DHShared)

	// now test if we can properly send data through the tunnel and that it triggers an incoming connection on the other end
	payload := []byte("asdf1234")

	err = router1.SendData(tunnel.ID(), payload)
	require.Nil(t, err)

	apiBuf := make([]byte, api.MaxSize)
	rd := bufio.NewReader(apiClient4)
	n, err := rd.Read(apiBuf)
	require.Nil(t, err)

	msg := apiBuf[:n]
	apiHdr := api.Header{}
	err = apiHdr.Parse(msg)
	require.Nil(t, err)
	assert.Equal(t, apiHdr.Type, api.TypeOnionTunnelIncoming)

	onionIncoming := api.OnionTunnelIncoming{}
	err = onionIncoming.Parse(msg[api.HeaderSize:])
	require.Nil(t, err)

	// check that our payload is coming through
	n, err = rd.Read(apiBuf)
	require.Nil(t, err)

	msg = apiBuf[:n]
	apiHdr = api.Header{}
	err = apiHdr.Parse(msg)
	require.Nil(t, err)
	assert.Equal(t, apiHdr.Type, api.TypeOnionTunnelData)

	onionData := api.OnionTunnelData{}
	err = onionData.Parse(msg[api.HeaderSize:])
	require.Nil(t, err)
	assert.Equal(t, payload, onionData.Data)
	assert.Equal(t, onionIncoming.TunnelID, onionData.TunnelID)

	// now we send some payload back through the tunnel and check if it appears on the tunnel creator side
	responsePayload := []byte("responsePayload")
	err = router4.SendData(onionIncoming.TunnelID, responsePayload)
	require.Nil(t, err)

	rd = bufio.NewReader(apiClient1)
	n, err = rd.Read(apiBuf)
	require.Nil(t, err)

	// check that our payload is coming through
	msg = apiBuf[:n]
	apiHdr = api.Header{}
	err = apiHdr.Parse(msg)
	require.Nil(t, err)
	assert.Equal(t, apiHdr.Type, api.TypeOnionTunnelData)

	onionData = api.OnionTunnelData{}
	err = onionData.Parse(msg[api.HeaderSize:])
	require.Nil(t, err)
	assert.Equal(t, tunnel.ID(), onionData.TunnelID)
	assert.Equal(t, responsePayload, onionData.Data)

	// now we tear down the tunnel from the receiving end
	err = router4.RemoveAPIConnectionFromTunnel(onionIncoming.TunnelID, apiConn4)
	require.Nil(t, err)
	time.Sleep(1 * time.Second) // wait for traffic to propagate
	assert.Equal(t, 0, len(router1.outgoingTunnels))
	assert.Equal(t, 0, len(router1.tunnels))

	assert.Equal(t, 0, len(router2.incomingTunnels))
	assert.Equal(t, 0, len(router2.tunnels))

	assert.Equal(t, 0, len(router3.incomingTunnels))
	assert.Equal(t, 0, len(router3.tunnels))

	assert.Equal(t, 0, len(router4.incomingTunnels))
	assert.Equal(t, 0, len(router4.tunnels))
}
