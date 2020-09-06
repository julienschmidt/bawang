package api

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensure that the implementations match the interface
var (
	_ Message = &RPSQuery{}
	_ Message = &RPSPeer{}
)

func TestRPSQuery(t *testing.T) {
	msg := new(RPSQuery)

	// check message type
	require.Equal(t, TypeRPSQuery, msg.Type())

	data := []byte{}
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, RPSQuery{}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestRPSPeer(t *testing.T) {
	msg := new(RPSPeer)

	// check message type
	require.Equal(t, TypeRPSPeer, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

	bytesAppTypeDHT := make([]byte, 2)
	binary.BigEndian.PutUint16(bytesAppTypeDHT, uint16(AppTypeDHT))

	bytesAppTypeGossip := make([]byte, 2)
	binary.BigEndian.PutUint16(bytesAppTypeGossip, uint16(AppTypeGossip))

	bytesAppTypeNSE := make([]byte, 2)
	binary.BigEndian.PutUint16(bytesAppTypeNSE, uint16(AppTypeNSE))

	bytesAppTypeOnion := make([]byte, 2)
	binary.BigEndian.PutUint16(bytesAppTypeOnion, uint16(AppTypeOnion))

	t.Run("IPv4EmptyPortMap", func(t *testing.T) {
		data := []byte{
			0, 1, 0, 0,
			2, 3, 4, 5,
			6, 7, 8, 9,
		}
		err := msg.Parse(data)
		require.Nil(t, err)
		require.Equal(t, RPSPeer{
			Port:        0x01,
			IPv6:        false,
			PortMap:     portMap{},
			Address:     net.IP{0x5, 0x4, 0x3, 0x2},
			DestHostKey: []byte{6, 7, 8, 9},
		}, *msg)

		buf := make([]byte, 4096)
		n, err := msg.Pack(buf)
		require.Nil(t, err)
		require.Equal(t, len(data), n)
		assert.Equal(t, data, buf[:n])
	})

	t.Run("IPv4InvalidPortMap", func(t *testing.T) {
		data := []byte{
			0, 1, 2, 0,
			42, 42, 3, 4,
			bytesAppTypeGossip[0], bytesAppTypeGossip[1], 5, 6,
			7, 8, 9, 10,
			11, 12, 13, 14,
		}
		err := msg.Parse(data)
		require.Equal(t, ErrInvalidAppType, err)

		buf := make([]byte, 4096)
		_, err = msg.Pack(buf)
		require.Equal(t, ErrInvalidAppType, err)
	})

	t.Run("IPv4PortMap", func(t *testing.T) {
		data := []byte{
			0, 1, 2, 0,
			bytesAppTypeDHT[0], bytesAppTypeDHT[1], 3, 4,
			bytesAppTypeGossip[0], bytesAppTypeGossip[1], 5, 6,
			7, 8, 9, 10,
			11, 12, 13, 14,
		}
		err := msg.Parse(data)
		require.Nil(t, err)
		require.Equal(t, RPSPeer{
			Port: 0x01,
			IPv6: false,
			PortMap: portMap{
				portMapping{AppTypeDHT, 0x304},
				portMapping{AppTypeGossip, 0x506},
			},
			Address:     net.IP{0xA, 0x9, 0x8, 0x7},
			DestHostKey: []byte{11, 12, 13, 14},
		}, *msg)

		assert.Equal(t, uint16(0x304), msg.PortMap.Get(AppTypeDHT))
		assert.Equal(t, uint16(0x506), msg.PortMap.Get(AppTypeGossip))
		assert.Equal(t, uint16(0), msg.PortMap.Get(AppTypeOnion))

		buf := make([]byte, 4096)
		n, err := msg.Pack(buf)
		require.Nil(t, err)
		require.Equal(t, len(data), n)
		assert.Equal(t, data, buf[:n])
	})

	t.Run("IPv6Valid", func(t *testing.T) {
		data := []byte{
			0, 1, 2, 0 | flagIPv6,
			bytesAppTypeNSE[0], bytesAppTypeNSE[1], 3, 4,
			bytesAppTypeOnion[0], bytesAppTypeOnion[1], 5, 6,
			7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
			23, 24, 25, 26,
		}
		err := msg.Parse(data)
		require.Nil(t, err)
		require.Equal(t, RPSPeer{
			Port: 0x01,
			IPv6: true,
			PortMap: portMap{
				portMapping{AppTypeNSE, 0x304},
				portMapping{AppTypeOnion, 0x506},
			},
			Address:     net.IP{22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7},
			DestHostKey: []byte{23, 24, 25, 26},
		}, *msg)

		assert.Equal(t, uint16(0), msg.PortMap.Get(AppTypeDHT))
		assert.Equal(t, uint16(0x304), msg.PortMap.Get(AppTypeNSE))
		assert.Equal(t, uint16(0x506), msg.PortMap.Get(AppTypeOnion))

		buf := make([]byte, 4096)
		n, err := msg.Pack(buf)
		require.Nil(t, err)
		require.Equal(t, len(data), n)
		assert.Equal(t, data, buf[:n])
	})

	t.Run("IPv6Short", func(t *testing.T) {
		data := []byte{
			0, 1, 2, 0 | flagIPv6,
			bytesAppTypeNSE[0], bytesAppTypeNSE[1], 3, 4,
			bytesAppTypeOnion[0], bytesAppTypeOnion[1], 5, 6,
			7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 23, 24, 25, 26,
		}
		err := msg.Parse(data)
		require.Equal(t, ErrInvalidMessage, err)
	})
}
