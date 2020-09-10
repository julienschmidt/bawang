package api

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectionSend(t *testing.T) {
	connSend, connRecv := net.Pipe()
	conn := Connection{
		Conn: connSend,
	}

	t.Run("nil msg", func(t *testing.T) {
		err := conn.Send(nil)
		require.NotNil(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		testData := []byte("test")
		msg := &MockMsg{
			ReportedType:       TypeOnionCover,
			ReportedPackedSize: len(testData),
			PackData:           testData,
		}

		var n int
		var sendErr, recvErr error
		var buf [64]byte
		go func() {
			sendErr = conn.Send(msg)
		}()

		var hdr Header
		recvErr = hdr.Read(connRecv)
		require.Nil(t, recvErr)
		require.Nil(t, sendErr)

		require.Equal(t, uint16(len(testData))+HeaderSize, hdr.Size)
		require.Equal(t, TypeOnionCover, hdr.Type)

		n, recvErr = connRecv.Read(buf[:])
		require.Nil(t, recvErr)
		require.Equal(t, len(testData), n)
		require.Equal(t, testData, buf[:n])
	})
}

func TestConnectionTerminate(t *testing.T) {
	// TODO: test for actual implementation
	var conn Connection
	err := conn.Terminate()
	require.Nil(t, err)
}
