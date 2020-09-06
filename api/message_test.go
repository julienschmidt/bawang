package api

import (
	"bytes"
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
		var buf [64]byte
		msg := &MockMsg{
			ReportedType:       TypeOnionCover,
			ReportedPackedSize: 42,
		}

		_, err := PackMessage(buf[:], msg)
		require.Equal(t, ErrInvalidMessage, err)
	})
}
