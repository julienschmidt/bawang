package main

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensure that the implementations match the interface
var (
	_ message = &msgOnionTunnelBuild{}
	_ message = &msgOnionTunnelReady{}
	_ message = &msgOnionTunnelIncoming{}
	_ message = &msgOnionTunnelDestroy{}
	_ message = &msgOnionTunnelData{}
	_ message = &msgOnionError{}
	_ message = &msgOnionCover{}
)

func TestMsgHeader(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	assert.Equal(t, msgHeaderSize, len(data))

	hdr, err := readMsgHeader(bytes.NewReader(data))
	assert.Nil(t, err)
	assert.Equal(t, msgHeader{
		Size: 0x0102,
		Type: 0x0304,
	}, hdr)
}

func TestMsgRPSQuery(t *testing.T) {
	msg := new(msgRPSQuery)

	// check message type
	require.Equal(t, msgTypeRPSQuery, msg.Type())

	data := []byte{}
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, msgRPSQuery{}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestMsgRPSPeer(t *testing.T) {
	msg := new(msgRPSPeer)

	// check message type
	require.Equal(t, msgTypeRPSPeer, msg.Type())

	// empty data
	assert.Equal(t, errInvalidMessage, msg.Parse([]byte{}))

	t.Run("IPv4EmptyPortMap", func(t *testing.T) {
		data := []byte{
			0, 1, 0, 0,
			2, 3, 4, 5,
			6, 7, 8, 9,
		}
		err := msg.Parse(data)
		require.Nil(t, err)
		require.Equal(t, msgRPSPeer{
			port:        0x01,
			ipv6:        false,
			portMap:     portMap{},
			address:     net.IP{0x5, 0x4, 0x3, 0x2},
			destHostKey: []byte{6, 7, 8, 9},
		}, *msg)

		buf := make([]byte, 4096)
		n, err := msg.Pack(buf)
		require.Nil(t, err)
		require.Equal(t, len(data), n)
		assert.Equal(t, data, buf[:n])
	})

	t.Run("IPv4PortMap", func(t *testing.T) {
		data := []byte{
			0, 1, 2, 0,
			0x02, 0x8A, 3, 4,
			0x01, 0xF4, 5, 6,
			7, 8, 9, 10,
			11, 12, 13, 14,
		}
		err := msg.Parse(data)
		require.Nil(t, err)
		require.Equal(t, msgRPSPeer{
			port: 0x01,
			ipv6: false,
			portMap: portMap{
				portMapping{appTypeDHT, 0x304},
				portMapping{appTypeGossip, 0x506},
			},
			address:     net.IP{0xA, 0x9, 0x8, 0x7},
			destHostKey: []byte{11, 12, 13, 14},
		}, *msg)

		buf := make([]byte, 4096)
		n, err := msg.Pack(buf)
		require.Nil(t, err)
		require.Equal(t, len(data), n)
		assert.Equal(t, data, buf[:n])
	})

	t.Run("IPv6", func(t *testing.T) {
		data := []byte{
			0, 1, 2, 0 | flagIPv6,
			0x02, 0x8A, 3, 4,
			0x01, 0xF4, 5, 6,
			7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
			23, 24, 25, 26,
		}
		err := msg.Parse(data)
		require.Nil(t, err)
		require.Equal(t, msgRPSPeer{
			port: 0x01,
			ipv6: true,
			portMap: portMap{
				portMapping{appTypeDHT, 0x304},
				portMapping{appTypeGossip, 0x506},
			},
			address:     net.IP{22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7},
			destHostKey: []byte{23, 24, 25, 26},
		}, *msg)

		buf := make([]byte, 4096)
		n, err := msg.Pack(buf)
		require.Nil(t, err)
		require.Equal(t, len(data), n)
		assert.Equal(t, data, buf[:n])
	})

}

func TestMsgOnionTunnelBuild(t *testing.T) {
	msg := new(msgOnionTunnelBuild)

	// check message type
	assert.Equal(t, msgTypeOnionTunnelBuild, msg.Type())

	// empty data
	assert.Equal(t, errInvalidMessage, msg.Parse([]byte{}))

	data := []byte{0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	err := msg.Parse(data)
	assert.Nil(t, err)
	assert.Equal(t, msgOnionTunnelBuild{
		ipv6:        false,
		onionPort:   0x102,
		address:     net.IP{0x6, 0x5, 0x4, 0x3},
		destHostKey: []byte{7, 8, 9},
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	assert.Nil(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestMsgOnionTunnelReady(t *testing.T) {
	msg := new(msgOnionTunnelReady)

	// check message type
	assert.Equal(t, msgTypeOnionTunnelReady, msg.Type())

	// empty data
	assert.Equal(t, errInvalidMessage, msg.Parse([]byte{}))

	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	err := msg.Parse(data)
	assert.Nil(t, err)
	assert.Equal(t, msgOnionTunnelReady{
		tunnelID:    0x1020304,
		destHostKey: []byte{5, 6, 7, 8, 9},
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	assert.Nil(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestMsgOnionTunnelIncoming(t *testing.T) {
	msg := new(msgOnionTunnelIncoming)

	// check message type
	assert.Equal(t, msgTypeOnionTunnelIncoming, msg.Type())

	// empty data
	assert.Equal(t, errInvalidMessage, msg.Parse([]byte{}))

	data := []byte{1, 2, 3, 4}
	err := msg.Parse(data)
	assert.Nil(t, err)
	assert.Equal(t, msgOnionTunnelIncoming{
		tunnelID: 0x1020304,
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	assert.Nil(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestMsgOnionTunnelDestroy(t *testing.T) {
	msg := new(msgOnionTunnelDestroy)

	// check message type
	assert.Equal(t, msgTypeOnionTunnelDestroy, msg.Type())

	// empty data
	assert.Equal(t, errInvalidMessage, msg.Parse([]byte{}))

	data := []byte{1, 2, 3, 4}
	err := msg.Parse(data)
	assert.Nil(t, err)
	assert.Equal(t, msgOnionTunnelDestroy{
		tunnelID: 0x1020304,
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	assert.Nil(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestMsgOnionTunnelData(t *testing.T) {
	msg := new(msgOnionTunnelData)

	// check message type
	assert.Equal(t, msgTypeOnionTunnelData, msg.Type())

	// empty data
	assert.Equal(t, errInvalidMessage, msg.Parse([]byte{}))

	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	err := msg.Parse(data)
	assert.Nil(t, err)
	assert.Equal(t, msgOnionTunnelData{
		tunnelID: 0x1020304,
		data:     []byte{5, 6, 7, 8, 9},
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	assert.Nil(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestMsgOnionError(t *testing.T) {
	msg := new(msgOnionError)

	// check message type
	assert.Equal(t, msgTypeOnionError, msg.Type())

	// empty data
	assert.Equal(t, errInvalidMessage, msg.Parse([]byte{}))

	data := []byte{1, 2, 0, 0, 3, 4, 5, 6}
	err := msg.Parse(data)
	assert.Nil(t, err)
	assert.Equal(t, msgOnionError{
		requestType: 0x102,
		tunnelID:    0x3040506,
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	assert.Nil(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestMsgOnionCover(t *testing.T) {
	msg := new(msgOnionCover)

	// check message type
	assert.Equal(t, msgTypeOnionCover, msg.Type())

	// empty data
	assert.Equal(t, errInvalidMessage, msg.Parse([]byte{}))

	data := []byte{1, 2, 0, 0}
	err := msg.Parse(data)
	assert.Nil(t, err)
	assert.Equal(t, msgOnionCover{
		coverSize: 0x102,
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	assert.Nil(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}
