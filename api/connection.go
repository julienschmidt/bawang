package api

import (
	"bufio"
	"io"
	"net"
)

// Connection abstracts a network connection on the API socket.
type Connection struct {
	nc     net.Conn
	rd     *bufio.Reader
	msgBuf [MaxSize]byte
}

// NewConnection initializes a new API Connection from a given network connection.
func NewConnection(nc net.Conn) *Connection {
	return &Connection{
		nc: nc,
		rd: bufio.NewReader(nc),
	}
}

// ReadMsg reads a message from the underlying network connection and returns its type and message body.
func (conn *Connection) ReadMsg() (msg Message, err error) {
	// read the message header
	var hdr Header
	if err = hdr.Read(conn.rd); err != nil {
		return nil, err
	}

	// ready message body
	body := conn.msgBuf[:hdr.Size]
	_, err = io.ReadFull(conn.rd, body)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}

	return parseMessage(hdr.Type, body)
}

// Send packs and sends a given message on the API connection.
func (conn *Connection) Send(msg Message) (err error) {
	n, err := PackMessage(conn.msgBuf[:], msg)
	if err != nil {
		return err
	}

	data := conn.msgBuf[:n]
	_, err = conn.nc.Write(data)
	return err
}

// SendError is a convenience helper to send an OnionError message with a given tunnel ID and message type.
func (conn *Connection) SendError(tunnelID uint32, msgType Type) (err error) {
	return conn.Send(&OnionError{
		TunnelID:    tunnelID,
		RequestType: msgType,
	})
}

// Terminate terminates the API connection and closes the underlying network connection.
func (conn *Connection) Terminate() (err error) {
	if conn.nc == nil {
		return nil
	}

	err = conn.nc.Close()
	return err
}
