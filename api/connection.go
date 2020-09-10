package api

import (
	"net"
)

type Connection struct {
	Conn net.Conn

	msgBuf [MaxSize]byte
}

func (conn *Connection) SendError(msgType Type, tunnelID uint32) (err error) {
	errMsg := OnionError{
		TunnelID: tunnelID,
		RequestType: msgType,
	}

	err = conn.Send(&errMsg)
	return err
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
	conn.Conn.Close()
	// TODO: implement
	return nil
}
