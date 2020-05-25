package message

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensure that the implementations match the interface
var (
	_ Message = &OnionTunnelBuild{}
	_ Message = &OnionTunnelReady{}
	_ Message = &OnionTunnelIncoming{}
	_ Message = &OnionTunnelDestroy{}
	_ Message = &OnionTunnelData{}
	_ Message = &OnionError{}
	_ Message = &OnionCover{}
)

func TestOnionTunnelBuild(t *testing.T) {
	msg := new(OnionTunnelBuild)

	// check message type
	require.Equal(t, TypeOnionTunnelBuild, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	data := []byte{0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, OnionTunnelBuild{
		IPv6:        false,
		OnionPort:   0x102,
		Address:     net.IP{0x6, 0x5, 0x4, 0x3},
		DestHostKey: []byte{7, 8, 9},
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestOnionTunnelReady(t *testing.T) {
	msg := new(OnionTunnelReady)

	// check message type
	require.Equal(t, TypeOnionTunnelReady, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, OnionTunnelReady{
		TunnelID:    0x1020304,
		DestHostKey: []byte{5, 6, 7, 8, 9},
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestOnionTunnelIncoming(t *testing.T) {
	msg := new(OnionTunnelIncoming)

	// check message type
	require.Equal(t, TypeOnionTunnelIncoming, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	data := []byte{1, 2, 3, 4}
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, OnionTunnelIncoming{
		TunnelID: 0x1020304,
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestOnionTunnelDestroy(t *testing.T) {
	msg := new(OnionTunnelDestroy)

	// check message type
	require.Equal(t, TypeOnionTunnelDestroy, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	data := []byte{1, 2, 3, 4}
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, OnionTunnelDestroy{
		TunnelID: 0x1020304,
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestMsgOnionTunnelData(t *testing.T) {
	msg := new(OnionTunnelData)

	// check message type
	require.Equal(t, TypeOnionTunnelData, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, OnionTunnelData{
		TunnelID: 0x1020304,
		Data:     []byte{5, 6, 7, 8, 9},
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestMsgOnionError(t *testing.T) {
	msg := new(OnionError)

	// check message type
	require.Equal(t, TypeOnionError, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	data := []byte{1, 2, 0, 0, 3, 4, 5, 6}
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, OnionError{
		RequestType: 0x102,
		TunnelID:    0x3040506,
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestMsgOnionCover(t *testing.T) {
	msg := new(OnionCover)

	// check message type
	require.Equal(t, TypeOnionCover, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	data := []byte{1, 2, 0, 0}
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, OnionCover{
		CoverSize: 0x102,
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}
