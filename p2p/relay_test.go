package p2p

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeDigest(t *testing.T) {
	payload := []byte("asdf1234")
	relayHdr := RelayHeader{
		Size:      RelayHeaderSize + uint16(len(payload)),
		RelayType: RelayTypeTunnelData,
		Counter:   [3]byte{0x00, 0x00, 0x01},
	}

	err := relayHdr.ComputeDigest(payload)
	require.Nil(t, err)

	// TODO: how to do proper testing here
}

func TestEncryptDecryptRelay(t *testing.T) {
	payload := []byte("asdf1234")
	buf := make([]byte, MaxRelayDataSize+RelayHeaderSize)

	prevCounter := uint32(123)

	relayData := RelayTunnelData{
		Data: payload,
	}

	var aesKey [32]byte
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.Nil(t, err)
	copy(aesKey[:], k[:32])

	newCounter, n, err := PackRelayMessage(buf, prevCounter, &relayData)
	require.Nil(t, err)
	assert.Greater(t, newCounter, prevCounter)
	assert.Equal(t, MaxRelayDataSize+RelayHeaderSize, n)
	log.Printf("payload in msg: %v\n", string(buf[RelayHeaderSize:RelayHeaderSize+len(payload)]))

	encMsg, err := EncryptRelay(buf[:n], &aesKey)
	require.Nil(t, err)

	ok, decMsg, err := DecryptRelay(encMsg, &aesKey)
	require.Nil(t, err)
	require.True(t, ok)

	relayHdr := RelayHeader{}
	err = relayHdr.Parse(decMsg[:RelayHeaderSize])
	require.Nil(t, err)

	ctr := make([]byte, 4)
	copy(ctr[1:], relayHdr.Counter[:])
	assert.Equal(t, newCounter, binary.BigEndian.Uint32(ctr))

	decRelayData := RelayTunnelData{}
	err = decRelayData.Parse(decMsg[RelayHeaderSize:int(relayHdr.Size)])
	require.Nil(t, err)
	assert.Equal(t, payload, decRelayData.Data)
}
