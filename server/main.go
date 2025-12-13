package main

import (
	"bufio"
	"log"
	"net"
	"strings"
)

func main() {
	listener, err := net.Listen("tcp4", "0.0.0.0:5678")
	if err != nil {
		log.Fatalf("Error accepting connection to server: %s", err.Error())
	}

	log.Println("[INFO] Listening on port 5678...")
	for {
		con, err := listener.Accept()
		if err != nil {
			log.Fatalf("Error accepting connection to server: %s", err.Error())
		}

		log.Println("Connection accepted!")
		go handle_connection(con)
	}
}

func handle_connection(con net.Conn) {

	remote_addr := con.RemoteAddr()
	defer con.Close()

	bufferedReader_ptr := bufio.NewReader(con)

	msg, err := bufferedReader_ptr.ReadString('\n')
	if err != nil {
		log.Printf("(con>%s) Failed to read all of the content present: %s\n", remote_addr, err.Error())
		return
	}

	log.Printf("(con>%s) Message: %s\n", remote_addr, strings.Trim(msg, "\n"))

	n_wrote, err := con.Write([]byte(msg))
	if n_wrote != len(msg) {
		log.Printf("(con>%s) Failed to write all of the content to client\n", remote_addr)
		return
	}
	if err != nil {
		log.Printf("(con>%s) Error when writing to the client: %s\n", remote_addr, err.Error())
		return
	}

	log.Printf("(con>%s) Bye!\n", remote_addr)
}
