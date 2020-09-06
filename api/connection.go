package api

import (
	"net"
)

type Connection struct {
	Conn net.Conn
}

func (conn *Connection) Send(msgType Type, msg Message) (err error) {
	// TODO: implement
	return nil
}

func (conn *Connection) Terminate() (err error) {
	// defer conn.Conn.Close()
	// TODO: implement
	return nil
}
