package api

import (
	"net"
)

type Connection struct {
	Conn net.Conn

	msgBuf [MaxSize]byte
}

func (conn *Connection) SendError(msgType Type, tunnelID uint32) (err error) {
	return conn.Send(&OnionError{
		TunnelID:    tunnelID,
		RequestType: msgType,
	})
}

func (conn *Connection) Send(msg Message) (err error) {
	// TODO: implement
	n, err := PackMessage(conn.msgBuf[:], msg)
	if err != nil {
		return err
	}

	data := conn.msgBuf[:n]
	_, err = conn.Conn.Write(data)
	return err
}

func (conn *Connection) Terminate() (err error) {
	if conn.Conn == nil {
		return nil
	}
	conn.Conn.Close()
	// TODO: implement
	return nil
}
