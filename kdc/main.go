package main

import (
	"bufio"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"log"
	"net"

	"github.com/p1nant0m/apollo/kdc/encryption"
	"github.com/p1nant0m/apollo/utils"
)

const (
	REGIST          uint8 = 1
	GETREMTOESERVER uint8 = 2
)

type ClientInfo struct {
	receiverAddr    string
	receiverPort    string
	receiverPublicK []byte
}

var storage map[string]*ClientInfo

func main() {
	storage = make(map[string]*ClientInfo)

	cert, err := tls.LoadX509KeyPair("../secret/server.pem", "../secret/server.key")
	if err != nil {
		log.Println(err)
		return
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("KDC Server Listening on " + ln.Addr().String())
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConn(conn)
	}
}

func keyGen() ([]byte, []byte) {
	privk, pubk := encryption.GenerateKeyPair(1024)
	pubk_byte := encryption.PublicKeyToBytes(pubk)
	privk_byte := encryption.PrivateKeyToBytes(privk)
	return pubk_byte, privk_byte
}

func registDataParser(data []byte) []byte {

	clientName := string(data[0:10])
	receiverAddr := string(utils.Unpadding(data[10:30]))
	receiverPort := string(utils.Unpadding(data[30:35]))
	clientInfo := &ClientInfo{
		receiverAddr: receiverAddr,
		receiverPort: receiverPort,
	}
	log.Printf("Receiving Registed Request: Client Name: %v receiverAddr: %v receiverPort %v", clientName, receiverAddr, receiverPort)

	pubk, privk := keyGen()
	clientInfo.receiverPublicK = pubk
	storage[clientName] = clientInfo

	return privk
}

func getRemoteSParser(data []byte) []byte {
	var response []byte
	response = append([]byte{}, []byte("\x00")...) // first byte set response status
	clientInfo, exist1 := storage[string(data[0:10])]
	targetServer, exist2 := storage[string(data[10:20])]
	signature := data[20:]

	log.Printf("client %v targetServer %v", string(data[0:10]), string(data[10:20]))

	// server whether has registed in KDC
	if !exist1 || !exist2 {
		response = append(response, []byte("client/remote server not exist")...)
		return response
	}

	log.Printf("Receive getRemoteS Request: ClientName %v targetServerIP %v targetServerPort %v", data[0:10], targetServer.receiverAddr, targetServer.receiverPort)

	// verify client signature
	publicK := encryption.BytesToPublicKey(clientInfo.receiverPublicK)
	h := sha256.New()
	h.Write(data[0:10])
	if err := verify(signature, publicK, h.Sum(nil)); err != nil {
		log.Println(err)
		response = append(response, []byte("verify failure")...)
		return response
	}

	// construct reponse data
	response = append([]byte{}, []byte("\x01")...)
	padding_Addr, _ := utils.Padding([]byte(targetServer.receiverAddr), 20)
	padding_Port, _ := utils.Padding([]byte(targetServer.receiverPort), 5)
	response = append(response, padding_Addr...)
	response = append(response, padding_Port...)
	response = append(response, targetServer.receiverPublicK...)
	return response
}

func verify(signature []byte, publickey *rsa.PublicKey, digest []byte) error {
	err := rsa.VerifyPSS(publickey, crypto.SHA256, digest, signature, nil)
	if err != nil {
		log.Print("could not verify signature: ", err)
		return errors.New("could not verify signature")
	}
	return nil
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		data := make([]byte, 500)
		n, err := r.Read(data)

		if err != nil || data == nil {
			log.Println(err)
			return
		}

		action := data[0]
		data = data[1:n]
		var response []byte
		switch action {
		case REGIST:
			priv_k := registDataParser(data)
			response = append([]byte{}, priv_k...)
		case GETREMTOESERVER:
			response = getRemoteSParser(data)
		}

		n, err = conn.Write(response)
		if err != nil {
			log.Println(n, err)
			return
		}
	}
}
