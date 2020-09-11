package p2p

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockMsg struct {
	ReportedType       Type
	ReportedPackedSize int
	PackData           []byte
	PackErr            error
}

func (mm *MockMsg) Type() Type {
	return mm.ReportedType
}

func (mm *MockMsg) Parse(data []byte) error {
	return nil
}

func (mm *MockMsg) Pack(buf []byte) (n int, err error) {
	if mm.PackData != nil {
		copy(buf, mm.PackData)
	}
	return len(mm.PackData), mm.PackErr
}

func (mm *MockMsg) PackedSize() (n int) {
	return mm.ReportedPackedSize
}

func TestHeaderParse(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		data := []byte{1, 2, 3, 4, 5}
		require.Equal(t, HeaderSize, len(data))

		var hdr Header
		err := hdr.Parse(data)
		require.Nil(t, err)
		assert.Equal(t, Header{
			TunnelID: 0x01020304,
			Type:     0x05,
		}, hdr)
	})

	t.Run("empty", func(t *testing.T) {
		var hdr Header
		err := hdr.Parse([]byte{})
		require.Equal(t, ErrInvalidMessage, err)
	})
}

func TestHeaderRead(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		data := []byte{1, 2, 3, 4, 5}
		require.Equal(t, HeaderSize, len(data))

		var hdr Header
		err := hdr.Read(bytes.NewReader(data))
		require.Nil(t, err)
		assert.Equal(t, Header{
			TunnelID: 0x01020304,
			Type:     0x05,
		}, hdr)
	})

	t.Run("empty", func(t *testing.T) {
		var hdr Header
		err := hdr.Read(bytes.NewReader([]byte{}))
		require.Error(t, err)
		require.Equal(t, "EOF", err.Error())
	})
}

func TestHeaderPack(t *testing.T) {
	in := Header{
		TunnelID: 42,
		Type:     TypeTunnelRelay,
	}
	var buf [5]byte
	in.Pack(buf[:])

	var out Header
	err := out.Parse(buf[:])
	require.Nil(t, err)
	assert.Equal(t, in, out)
}

func TestPackMessage(t *testing.T) {
	const tunnelID = 42

	t.Run("valid", func(t *testing.T) {
		var buf [MaxSize]byte
		msg := new(TunnelDestroy)

		n, err := PackMessage(buf[:], tunnelID, msg)
		require.Nil(t, err)
		require.Equal(t, MaxSize, n)

		var hdr Header
		err = hdr.Parse(buf[:])
		require.Nil(t, err)
		require.Equal(t, msg.Type(), hdr.Type)
	})

	t.Run("invalid msg", func(t *testing.T) {
		packErr := errors.New("pack err")

		var buf [MaxSize]byte
		msg := &MockMsg{
			ReportedType:       TypeTunnelDestroy,
			ReportedPackedSize: 42,
			PackErr:            packErr,
		}

		_, err := PackMessage(buf[:], tunnelID, msg)
		require.Equal(t, packErr, err)

		msg.PackErr = nil

		_, err = PackMessage(buf[:], tunnelID, msg)
		require.Equal(t, ErrInvalidMessage, err)

		_, err = PackMessage(buf[:], tunnelID, nil)
		require.Equal(t, ErrInvalidMessage, err)
	})
}
