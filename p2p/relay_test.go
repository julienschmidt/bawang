package p2p

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	_ RelayMessage = &RelayTunnelExtend{}
	_ RelayMessage = &RelayTunnelExtended{}
	_ RelayMessage = &RelayTunnelData{}
	// TODO: _ RelayMessage = &RelayTunnelCover{}
)

type MockRelayMsg struct {
	ReportedType       RelayType
	ReportedPackedSize int
	PackData           []byte
	PackErr            error
}

func (mrm *MockRelayMsg) Type() RelayType {
	return mrm.ReportedType
}

func (mrm *MockRelayMsg) Parse(data []byte) error {
	return nil
}

func (mrm *MockRelayMsg) Pack(buf []byte) (n int, err error) {
	if mrm.PackData != nil {
		copy(buf, mrm.PackData)
	}
	return len(mrm.PackData), mrm.PackErr
}

func (mrm *MockRelayMsg) PackedSize() (n int) {
	return mrm.ReportedPackedSize
}

func TestRelayHeaderParse(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		require.Equal(t, RelayHeaderSize, len(data))

		var hdr RelayHeader
		err := hdr.Parse(data)
		require.Nil(t, err)
		assert.Equal(t, RelayHeader{
			Counter:   [3]byte{1, 2, 3},
			RelayType: 4,
			Size:      0x0506,
			Digest:    [8]byte{8, 9, 10, 11, 12, 13, 14, 15},
		}, hdr)
	})

	t.Run("empty", func(t *testing.T) {
		var hdr RelayHeader
		err := hdr.Parse([]byte{})
		require.Equal(t, ErrInvalidMessage, err)
	})
}

func TestRelayHeaderPack(t *testing.T) {
	in := RelayHeader{
		Counter:   [3]byte{1, 2, 3},
		RelayType: 4,
		Size:      0x0506,
		Digest:    [8]byte{8, 9, 10, 11, 12, 13, 14, 15},
	}
	var buf [15]byte
	err := in.Pack(buf[:])
	require.Nil(t, err)

	err = in.Pack([]byte{})
	require.Equal(t, err, ErrBufferTooSmall)

	var out RelayHeader
	err = out.Parse(buf[:])
	require.Nil(t, err)
	assert.Equal(t, in, out)
}

func TestRelayHeaderComputeDigest(t *testing.T) {
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

func TestPackRelayMessage(t *testing.T) {
	const oldCounter = 42

	t.Run("valid", func(t *testing.T) {
		var buf [MaxRelaySize]byte
		msg := new(RelayTunnelData)

		ctr, n, err := PackRelayMessage(buf[:], oldCounter, msg)
		require.Nil(t, err)
		require.Equal(t, MaxRelaySize, n)
		require.Greater(t, ctr, uint32(oldCounter))

		var hdr RelayHeader
		err = hdr.Parse(buf[:])
		require.Nil(t, err)
		require.Equal(t, msg.Type(), hdr.RelayType)
	})

	t.Run("invalid", func(t *testing.T) {
		var buf [MaxSize]byte

		packErr := errors.New("pack err")
		msg := &MockRelayMsg{
			ReportedType:       RelayTypeTunnelData,
			ReportedPackedSize: 42,
			PackErr:            packErr,
		}

		_, _, err := PackRelayMessage(buf[:42], oldCounter, msg)
		require.Equal(t, ErrBufferTooSmall, err)

		_, _, err = PackRelayMessage(buf[:], oldCounter, msg)
		require.Equal(t, packErr, err)

		msg.PackErr = nil

		_, _, err = PackRelayMessage(buf[:], oldCounter, msg)
		require.Equal(t, ErrInvalidMessage, err)

		_, _, err = PackRelayMessage(buf[:], oldCounter, nil)
		require.Equal(t, ErrInvalidMessage, err)
	})
}

func TestRelayEncryptDecrypt(t *testing.T) {
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

func TestRelayTunnelExtend(t *testing.T) {
	msg := new(RelayTunnelExtend)

	// check message type
	require.Equal(t, RelayTypeTunnelExtend, msg.Type())

	// empty data
	assert.Equal(t, ErrInvalidMessage, msg.Parse([]byte{}))

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

	var encKey [512]byte
	encKey[0] = 0x11
	encKey[511] = 0xff

	t.Run("IPv4", func(t *testing.T) {
		data := make([]byte, 520)
		data[1] = 0 // IPv4

		// IPv4 addr
		data[4] = 1
		data[5] = 2
		data[6] = 3
		data[7] = 4

		// DH pub key
		data[8] = encKey[0]     // key start
		data[519] = encKey[511] // key end

		err := msg.Parse(data)
		require.Nil(t, err)
		require.Equal(t, RelayTunnelExtend{
			IPv6:        false,
			Address:     net.IP{4, 3, 2, 1},
			EncDHPubKey: encKey,
		}, *msg)

		buf := make([]byte, 4096)
		n, err := msg.Pack(buf)
		require.Nil(t, err)
		require.Equal(t, len(data), n)
		assert.Equal(t, data, buf[:n])
	})

	t.Run("IPv6", func(t *testing.T) {
		data := make([]byte, 532)
		data[1] = 1 // IPv6

		// IPv6 addr
		data[4] = 1
		data[5] = 2
		data[6] = 3
		data[7] = 4
		data[8] = 5
		data[9] = 6
		data[10] = 7
		data[11] = 8
		data[12] = 9
		data[13] = 10
		data[14] = 11
		data[15] = 12
		data[16] = 13
		data[17] = 14
		data[18] = 15
		data[19] = 16

		// DH pub key
		data[20] = encKey[0]    // key start
		data[531] = encKey[511] // key end

		err := msg.Parse(data[:520])
		assert.Equal(t, ErrInvalidMessage, err)

		err = msg.Parse(data)
		require.Nil(t, err)
		require.Equal(t, RelayTunnelExtend{
			IPv6:        true,
			Address:     net.IP{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
			EncDHPubKey: encKey,
		}, *msg)

		buf := make([]byte, 4096)
		n, err := msg.Pack(buf)
		require.Nil(t, err)
		require.Equal(t, len(data), n)
		assert.Equal(t, data, buf[:n])
	})
}

func TestRelayTunnelExtended(t *testing.T) {
	msg := new(RelayTunnelExtended)

	// check message type
	require.Equal(t, RelayTypeTunnelExtended, msg.Type())

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

	data := make([]byte, 64)
	data[0] = pubKey[0]      // pub key start
	data[31] = pubKey[31]    // pub key end
	data[32] = sharedKey[0]  // shared key start
	data[63] = sharedKey[31] // shared key end

	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, RelayTunnelExtended{
		DHPubKey:      pubKey,
		SharedKeyHash: sharedKey,
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}

func TestRelayTunnelData(t *testing.T) {
	msg := new(RelayTunnelData)

	// check message type
	require.Equal(t, RelayTypeTunnelData, msg.Type())

	data := make([]byte, 42)
	data[0] = 0x11
	data[41] = 0xff

	msg.Data = data

	// too small buf for packing
	_, packErr := msg.Pack([]byte{})
	assert.Equal(t, ErrBufferTooSmall, packErr)

	err := msg.Parse(data)
	require.Nil(t, err)
	require.Equal(t, RelayTunnelData{
		Data: data,
	}, *msg)

	buf := make([]byte, 4096)
	n, err := msg.Pack(buf)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	assert.Equal(t, data, buf[:n])
}
