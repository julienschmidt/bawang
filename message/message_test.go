package message

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeader(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	require.Equal(t, HeaderSize, len(data))

	var hdr Header
	err := hdr.Read(bytes.NewReader(data))
	require.Nil(t, err)
	assert.Equal(t, Header{
		Size: 0x0102,
		Type: 0x0304,
	}, hdr)
}
