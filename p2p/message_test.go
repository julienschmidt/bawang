package p2p

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)


func TestHeader(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	require.Equal(t, HeaderSize, len(data))

	var hdr Header
	err := hdr.Read(bytes.NewReader(data))
	require.Nil(t, err)
	assert.Equal(t, Header{
		TunnelID: 0x01020304,
		Type: 0x05,
	}, hdr)
}
