package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"strings"
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

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

	t.Run("IPv4", func(t *testing.T) {
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
	})

	t.Run("IPv6Valid", func(t *testing.T) {
		data := []byte{0, flagIPv6, 1, 2, 3, 4, 5, 6, 7, 8, 9,
			10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}
		err := msg.Parse(data)
		require.Nil(t, err)
		require.Equal(t, OnionTunnelBuild{
			IPv6:        true,
			OnionPort:   0x102,
			Address:     net.IP{0x12, 0x11, 0x010, 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3},
			DestHostKey: []byte{19, 20, 21},
		}, *msg)

		buf := make([]byte, 4096)
		n, err := msg.Pack(buf)
		require.Nil(t, err)
		require.Equal(t, len(data), n)
		assert.Equal(t, data, buf[:n])
	})

	t.Run("IPv6Short", func(t *testing.T) {
		data := []byte{0, flagIPv6, 1, 2, 3, 4, 5, 6, 7, 8, 9}
		err := msg.Parse(data)
		require.Equal(t, ErrInvalidMessage, err)
	})

	t.Run("ParseHostKey invalid", func(t *testing.T) {
		buildMsg := OnionTunnelBuild{
			DestHostKey: []byte{19, 20, 21},
		}

		key, err := buildMsg.ParseHostKey()
		require.NotNil(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "invalid hostkey:"))
		require.Nil(t, key)
	})

	t.Run("ParseHostKey valid", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 4096)
		require.Nil(t, err)
		pubKey := rsa.PublicKey{N: privKey.N, E: privKey.E}

		pubkeyBytes := x509.MarshalPKCS1PublicKey(&pubKey)
		buildMsg := OnionTunnelBuild{
			DestHostKey: pubkeyBytes,
		}

		key, err := buildMsg.ParseHostKey()
		require.Nil(t, err)
		require.NotNil(t, key)
	})
}

func TestOnionTunnelReady(t *testing.T) {
	msg := new(OnionTunnelReady)

	// check message type
	require.Equal(t, TypeOnionTunnelReady, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

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

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

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

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

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

func TestOnionTunnelData(t *testing.T) {
	msg := new(OnionTunnelData)

	// check message type
	require.Equal(t, TypeOnionTunnelData, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

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

func TestOnionError(t *testing.T) {
	msg := new(OnionError)

	// check message type
	require.Equal(t, TypeOnionError, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

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

func TestOnionCover(t *testing.T) {
	msg := new(OnionCover)

	// check message type
	require.Equal(t, TypeOnionCover, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

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
