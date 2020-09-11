package api

import (
	"net"
)

// Connection abstracts a network connection on the API socket.
type Connection struct {
	Conn net.Conn

	msgBuf [MaxSize]byte
}

// Send packs and sends a given message on the API connection.
func (conn *Connection) Send(msg Message) (err error) {
	n, err := PackMessage(conn.msgBuf[:], msg)
	if err != nil {
		return err
	}

	data := conn.msgBuf[:n]
	_, err = conn.Conn.Write(data)
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
	if conn.Conn == nil {
		return nil
	}

	conn.Conn.Close()
	return nil
}
