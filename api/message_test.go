package api

import (
	"bytes"
	"errors"
	"net"
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
		data := []byte{1, 2, 3, 4}
		require.Equal(t, HeaderSize, len(data))

		var hdr Header
		err := hdr.Parse(data)
		require.Nil(t, err)
		assert.Equal(t, Header{
			Size: 0x0102,
			Type: 0x0304,
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
		data := []byte{1, 2, 3, 4}
		require.Equal(t, HeaderSize, len(data))

		var hdr Header
		err := hdr.Read(bytes.NewReader(data))
		require.Nil(t, err)
		assert.Equal(t, Header{
			Size: 0x0102,
			Type: 0x0304,
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
		Size: 42,
		Type: TypeGossipAnnounce,
	}
	var buf [4]byte
	in.Pack(buf[:])

	var out Header
	err := out.Parse(buf[:])
	require.Nil(t, err)
	assert.Equal(t, in, out)
}

func TestPackMessage(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		var buf [64]byte
		msg := new(OnionCover)

		n, err := PackMessage(buf[:], msg)
		require.Nil(t, err)
		require.Equal(t, HeaderSize+msg.PackedSize(), n)

		var hdr Header
		err = hdr.Parse(buf[:])
		require.Nil(t, err)
		require.Equal(t, msg.Type(), hdr.Type)
		require.Equal(t, uint16(HeaderSize+msg.PackedSize()), hdr.Size)
	})

	t.Run("invalid msg", func(t *testing.T) {
		packErr := errors.New("pack err")

		var buf [64]byte
		msg := &MockMsg{
			ReportedType:       TypeOnionCover,
			ReportedPackedSize: 42,
			PackErr:            packErr,
		}

		_, err := PackMessage(buf[:], msg)
		require.Equal(t, packErr, err)

		msg.PackErr = nil

		_, err = PackMessage(buf[:], msg)
		require.Equal(t, ErrInvalidMessage, err)

		_, err = PackMessage(buf[:], nil)
		require.Equal(t, ErrInvalidMessage, err)
	})
}

func TestParseMessage(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		var buf [MaxSize]byte

		inputs := []Message{
			&OnionTunnelBuild{
				IPv6:    false,
				Address: net.IP{1, 2, 3, 4},
			},
			&OnionTunnelReady{},
			&OnionTunnelIncoming{},
			&OnionTunnelDestroy{},
			&OnionTunnelData{},
			&OnionError{},
			&OnionCover{},
		}

		for _, input := range inputs {
			n, err := input.Pack(buf[:])
			require.Nil(t, err)

			msg, err := parseMessage(input.Type(), buf[:n])
			require.Nil(t, err)
			require.Equal(t, input.Type(), msg.Type())
		}
	})

	t.Run("invalid", func(t *testing.T) {
		msg, err := parseMessage(0, nil)
		require.EqualError(t, err, ErrInvalidMessage.Error())
		require.Nil(t, msg)
	})
}
