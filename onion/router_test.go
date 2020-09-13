package onion

import (
	"bawang/p2p"
	"bufio"
	"crypto/rsa"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"bawang/api"
	"bawang/config"
	"bawang/rps"
)

type mockRPS struct {
	peers []*rps.Peer
}

func (r *mockRPS) GetPeer() (peer *rps.Peer, err error) {
	if len(r.peers) > 0 {
		peer = r.peers[0]
		r.peers = r.peers[1:]
		return peer, nil
	}
	return nil, errors.New("no peers")
}

func (r *mockRPS) SampleIntermediatePeers(n int, target *rps.Peer) (peers []*rps.Peer, err error) {
	peers = make([]*rps.Peer, n)
	for i := 0; i < n-1; i++ {
		peers[i], err = r.GetPeer()
		if err != nil {
			return nil, err
		}
	}
	peers[n-1] = target
	return peers, nil
}

func (r *mockRPS) Close() {}

var _ rps.RPS = &mockRPS{}

func TestOnionNewRouter(t *testing.T) {
	router, err := NewRouter(nil)
	require.NotNil(t, err)
	require.Nil(t, router)
}

func TestOnionRouterBuildTunnel(t *testing.T) {
	// load config files
	cfgPeer1 := config.Config{}
	err := cfgPeer1.FromFile("../.testing/bootstrap.conf")
	require.Nil(t, err)

	cfgPeer2 := config.Config{}
	err = cfgPeer2.FromFile("../.testing/peer-2.conf")
	require.Nil(t, err)

	cfgPeer3 := config.Config{}
	err = cfgPeer3.FromFile("../.testing/peer-3.conf")
	require.Nil(t, err)

	cfgPeer4 := config.Config{}
	err = cfgPeer4.FromFile("../.testing/peer-4.conf")
	require.Nil(t, err)

	// setup peers
	intermediateHops := []*rps.Peer{
		{Port: uint16(cfgPeer2.P2PPort), Address: net.ParseIP(cfgPeer2.P2PHostname), HostKey: &rsa.PublicKey{N: cfgPeer2.HostKey.N, E: cfgPeer2.HostKey.E}},
		{Port: uint16(cfgPeer3.P2PPort), Address: net.ParseIP(cfgPeer3.P2PHostname), HostKey: &rsa.PublicKey{N: cfgPeer3.HostKey.N, E: cfgPeer3.HostKey.E}},
	}
	targetPeer := rps.Peer{Port: uint16(cfgPeer4.P2PPort), Address: net.ParseIP(cfgPeer4.P2PHostname), HostKey: &rsa.PublicKey{N: cfgPeer4.HostKey.N, E: cfgPeer4.HostKey.E}}

	// setup routers
	router1 := newRouterWithRPS(&cfgPeer1, &mockRPS{
		peers: intermediateHops,
	})
	require.NotNil(t, router1)

	router2 := newRouterWithRPS(&cfgPeer2, nil)
	require.NotNil(t, router2)

	router3 := newRouterWithRPS(&cfgPeer3, nil)
	require.NotNil(t, router3)

	router4 := newRouterWithRPS(&cfgPeer4, nil)
	require.NotNil(t, router4)

	// register dummy API conns
	apiServer1, apiClient1 := net.Pipe()
	apiConn1 := api.NewConnection(apiServer1)
	router1.RegisterAPIConnection(apiConn1)
	require.Len(t, router1.apiConnections, 1)

	apiServer4, apiClient4 := net.Pipe()
	apiConn4 := api.NewConnection(apiServer4)
	router4.RegisterAPIConnection(apiConn4)
	require.Len(t, router4.apiConnections, 1)

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
	tunnel, err := router1.buildNewTunnel(&targetPeer, apiConn1)
	require.Nil(t, err)
	require.NotNil(t, tunnel)

	assert.Equal(t, len(intermediateHops)+1, len(tunnel.hops))
	assert.NotNil(t, tunnel.hops[0].DHShared)
	assert.NotNil(t, tunnel.hops[1].DHShared)
	assert.NotNil(t, tunnel.hops[2].DHShared)

	go router1.HandleOutgoingTunnel(tunnel)

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
	err = router4.RemoveAPIConnection(apiConn4)
	require.Nil(t, err)

	// simulate cleaning at beginning of new round
	router4.removeUnusedTunnels()

	// empty the pipe buffer of api conn 1 otherwise writes will block since pipes are not buffered
	_, _ = rd.Read(apiBuf) // here

	// wait for traffic to propagate
	time.Sleep(2 * time.Second)

	assert.Equal(t, 0, len(router1.outgoingTunnels))
	assert.Equal(t, 0, len(router1.tunnels))

	assert.Equal(t, 0, len(router2.incomingTunnels))
	assert.Equal(t, 0, len(router2.tunnels))

	assert.Equal(t, 0, len(router3.incomingTunnels))
	assert.Equal(t, 0, len(router3.tunnels))

	assert.Equal(t, 0, len(router4.incomingTunnels))
	assert.Equal(t, 0, len(router4.tunnels))

	close(quitChan)
}

func TestRouter_HandleRounds(t *testing.T) {
	// load config files
	cfgPeer1 := config.Config{}
	err := cfgPeer1.FromFile("../.testing/bootstrap.conf")
	require.Nil(t, err)

	cfgPeer2 := config.Config{}
	err = cfgPeer2.FromFile("../.testing/peer-2.conf")
	require.Nil(t, err)

	cfgPeer3 := config.Config{}
	err = cfgPeer3.FromFile("../.testing/peer-3.conf")
	require.Nil(t, err)

	cfgPeer4 := config.Config{}
	err = cfgPeer4.FromFile("../.testing/peer-4.conf")
	require.Nil(t, err)

	// setup peers
	intermediateHops := []*rps.Peer{
		{Port: uint16(cfgPeer2.P2PPort), Address: net.ParseIP(cfgPeer2.P2PHostname), HostKey: &rsa.PublicKey{N: cfgPeer2.HostKey.N, E: cfgPeer2.HostKey.E}},
		{Port: uint16(cfgPeer3.P2PPort), Address: net.ParseIP(cfgPeer3.P2PHostname), HostKey: &rsa.PublicKey{N: cfgPeer3.HostKey.N, E: cfgPeer3.HostKey.E}},
		{Port: uint16(cfgPeer4.P2PPort), Address: net.ParseIP(cfgPeer4.P2PHostname), HostKey: &rsa.PublicKey{N: cfgPeer4.HostKey.N, E: cfgPeer4.HostKey.E}},
	}

	// setup routers
	router1 := newRouterWithRPS(&cfgPeer1, &mockRPS{
		peers: intermediateHops,
	})
	require.NotNil(t, router1)

	router2 := newRouterWithRPS(&cfgPeer2, nil)
	require.NotNil(t, router2)

	router3 := newRouterWithRPS(&cfgPeer3, nil)
	require.NotNil(t, router3)

	router4 := newRouterWithRPS(&cfgPeer4, nil)
	require.NotNil(t, router4)
	errChanRounds := make(chan error)
	quitChan := make(chan struct{})
	errChanOnion1 := make(chan error)
	errChanOnion2 := make(chan error)
	errChanOnion3 := make(chan error)
	errChanOnion4 := make(chan error)

	go ListenOnionSocket(&cfgPeer1, router1, errChanOnion1, quitChan)
	go ListenOnionSocket(&cfgPeer2, router2, errChanOnion2, quitChan)
	go ListenOnionSocket(&cfgPeer3, router3, errChanOnion3, quitChan)
	go ListenOnionSocket(&cfgPeer4, router4, errChanOnion4, quitChan)

	time.Sleep(1 * time.Second)
	go router1.HandleRounds(errChanRounds, quitChan)
	time.Sleep(1 * time.Second)

	assert.NotNil(t, router1.coverTunnel)
	assert.Equal(t, 1, len(router1.outgoingTunnels))
	assert.Equal(t, 1, len(router1.tunnels))

	err = router1.SendCover(2 * p2p.MessageSize + 1)
	assert.Nil(t, err)
}
