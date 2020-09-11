package p2p

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	_ Message = &TunnelCreate{}
	_ Message = &TunnelCreated{}
	_ Message = &TunnelDestroy{}
	_ Message = &TunnelRelay{}
)

func TestTunnelCreate(t *testing.T) {
	msg := new(TunnelCreate)

	// check message type
	require.Equal(t, TypeTunnelCreate, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

	var encKey [512]byte
	encKey[0] = 0x11
	encKey[511] = 0xff

	data := make([]byte, 515)
	data[0] = 1             // version
	data[3] = encKey[0]     // pub key start
	data[514] = encKey[511] // pub key end
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, TunnelCreate{
		Version:     1,
		EncDHPubKey: encKey,
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestTunnelCreated(t *testing.T) {
	msg := new(TunnelCreated)

	// check message type
	require.Equal(t, TypeTunnelCreated, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

	var pubKey [32]byte
	pubKey[0] = 0x11
	pubKey[31] = 0xff

	var sharedKey [32]byte
	sharedKey[0] = 0x22
	sharedKey[31] = 0xee

	data := make([]byte, 67)
	data[3] = pubKey[0]      // pub key start
	data[34] = pubKey[31]    // pub key end
	data[35] = sharedKey[0]  // shared key start
	data[66] = sharedKey[31] // shared key end
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, TunnelCreated{
		DHPubKey:      pubKey,
		SharedKeyHash: sharedKey,
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestTunnelDestroy(t *testing.T) {
	msg := new(TunnelDestroy)

	// check message type
	require.Equal(t, TypeTunnelDestroy, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

	data := make([]byte, 3)
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, TunnelDestroy{}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestTunnelRelay(t *testing.T) {
	msg := new(TunnelRelay)

	// check message type
	require.Equal(t, TypeTunnelRelay, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	var relayData [MaxRelayDataSize]byte
	relayData[0] = 0x11
	relayData[MaxRelayDataSize-1] = 0xff

	data := relayData[:]
	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, TunnelRelay{
		EncData: relayData,
	}, *msg)

	require.Equal(t, MaxRelaySize, msg.PackedSize())

	var panicMsg string
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicMsg = fmt.Sprintf("%+v", r)
			}
		}()

		_, _ = msg.Pack(nil)
	}()

	require.Equal(t, "must use PackRelayMessage instead", panicMsg)
}
