package api

import (
	"net"
)

type Connection struct {
	Conn net.Conn

	msgBuf [MaxSize]byte
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
	// defer conn.Conn.Close()
	// TODO: implement
	return nil
}
