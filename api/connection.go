package api

import (
	"net"
)

type Connection struct {
	Conn net.Conn
}

func (conn *Connection) Send(msgType Type, msg Message) (err error) {
	// TODO: implement
	return
}

func (conn *Connection) Terminate() (err error) {
	// TODO: implement
	return
}
