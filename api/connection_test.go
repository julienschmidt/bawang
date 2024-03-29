package api

import (
	"io"
	"io/ioutil"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectionReadMsg(t *testing.T) {
	t.Run("EOF when closed", func(t *testing.T) {
		connRecv, connSend := net.Pipe()
		connSend.Close() // close immediately
		defer connRecv.Close()

		conn := NewConnection(connRecv)
		msg, err := conn.ReadMsg()
		require.EqualError(t, err, io.EOF.Error())
		require.Nil(t, msg)
	})

	t.Run("short body", func(t *testing.T) {
		connRecv, connSend := net.Pipe()
		defer connSend.Close()
		defer connRecv.Close()

		go func() {
			var buf [64]byte
			hdr := Header{
				Size: 8,
				Type: TypeOnionCover,
			}
			hdr.Pack(buf[:])
			connSend.Write(buf[:HeaderSize])
			connSend.Close()
		}()

		conn := NewConnection(connRecv)
		msg, err := conn.ReadMsg()
		require.EqualError(t, err, io.ErrUnexpectedEOF.Error())
		require.Nil(t, msg)
	})

	t.Run("valid", func(t *testing.T) {
		connRecv, connSend := net.Pipe()
		defer connSend.Close()
		defer connRecv.Close()

		go func() {
			var buf [64]byte

			var msg OnionCover
			hdr := Header{
				Size: uint16(msg.PackedSize()),
				Type: TypeOnionCover,
			}
			hdr.Pack(buf[:])
			buf[HeaderSize] = 0x11
			buf[HeaderSize+7] = 0xff
			connSend.Write(buf[:HeaderSize+msg.PackedSize()])
			connSend.Close()
		}()

		conn := NewConnection(connRecv)
		msg, err := conn.ReadMsg()
		require.Nil(t, err)
		require.Equal(t, TypeOnionCover, msg.Type())
	})
}

func TestConnectionSend(t *testing.T) {
	connSend, connRecv := net.Pipe()
	conn := NewConnection(connSend)

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
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			sendErr = conn.Send(msg)
			connSend.Close()
			wg.Done()
		}()

		var hdr Header
		recvErr = hdr.Read(connRecv)
		require.Nil(t, recvErr)

		require.Equal(t, uint16(len(testData))+HeaderSize, hdr.Size)
		require.Equal(t, TypeOnionCover, hdr.Type)

		n, recvErr = connRecv.Read(buf[:])
		require.Nil(t, recvErr)
		require.Equal(t, len(testData), n)
		require.Equal(t, testData, buf[:n])

		extraData, _ := ioutil.ReadAll(connRecv)
		require.Equal(t, []byte{}, extraData)

		wg.Wait()
		require.Nil(t, sendErr)
	})
}

func TestConnectionSendError(t *testing.T) {
	connSend, connRecv := net.Pipe()
	conn := NewConnection(connSend)

	var n int
	var sendErr, recvErr error
	var buf [64]byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		sendErr = conn.SendError(42, TypeOnionCover)
		connSend.Close()
		wg.Done()
	}()

	var hdr Header
	recvErr = hdr.Read(connRecv)
	require.Nil(t, recvErr)

	var onionError OnionError
	require.Equal(t, uint16(HeaderSize+onionError.PackedSize()), hdr.Size)
	require.Equal(t, TypeOnionError, hdr.Type)

	n, recvErr = connRecv.Read(buf[:])
	require.Nil(t, recvErr)
	require.Equal(t, onionError.PackedSize(), n)
	parseErr := onionError.Parse(buf[:n])
	require.Nil(t, parseErr)
	require.Equal(t, uint32(42), onionError.TunnelID)
	require.Equal(t, TypeOnionCover, onionError.RequestType)

	extraData, _ := ioutil.ReadAll(connRecv)
	require.Equal(t, []byte{}, extraData)

	wg.Wait()
	require.Nil(t, sendErr)
}

func TestConnectionTerminate(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		var conn Connection
		err := conn.Terminate()
		require.Nil(t, err)
	})

	t.Run("conn closed", func(t *testing.T) {
		connSend, connRecv := net.Pipe()
		defer connSend.Close()
		defer connRecv.Close()
		conn := NewConnection(connSend)

		err := conn.Terminate()
		require.Nil(t, err)

		var hdr Header
		recvErr := hdr.Read(connRecv)
		require.EqualError(t, recvErr, io.EOF.Error()) // EOF signals that the conn is closed
	})
}
