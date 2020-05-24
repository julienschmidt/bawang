package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"net"
)

func handleAPIConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		// try and read the packet header
		buf := make([]byte, 4)
		n, err := io.ReadFull(reader, buf)
		if err != nil || n != 4 {
			log.Printf("Error reading packet header: %v", err)
			break
		}

		size := binary.BigEndian.Uint16(buf[:2])
		//messageType := binary.BigEndian.Uint16(buf[2:])
		// TODO: sanity checks for package size
		packet := make([]byte, size)

		n, err = io.ReadFull(reader, packet)
		if err != nil || n != int(size) {
			log.Printf("Error reading main packet: %v", err)
			break
		}

		// TODO: call packet processing function
		// something like
		// switch (messageType) do something with packet
	}
}

func listenAPISocket(cfg *Config) error {
	ln, err := net.Listen("tcp", cfg.OnionAPIAddress)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// TODO: error on client connection
			log.Println("Error when accepting client connection")
			continue
		}
		log.Println("Received connection")

		go handleAPIConnection(conn)
	}
}
