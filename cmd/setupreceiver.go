/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"bufio"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/p1nant0m/apollo/kdc/encryption"
	"github.com/spf13/cobra"
)

// setupreceiverCmd represents the setupreceiver command
var setupreceiverCmd = &cobra.Command{
	Use:   "setupreceiver",
	Short: "Set up receiver listening on given port",
	Long:  `Set up receiver listening on given port to receive any encrypted message from other server`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("setupreceiver called")
		handler(cmd.Flag("listen-port").Value.String(), cmd.Flag("privk-file").Value.String())
	},
}

func handler(port string, privkfs string) {
	privkfs_raw, err := ioutil.ReadFile(privkfs)
	if err != nil {
		log.Fatalf("fail to read files from %v", privkfs)
	}

	privK := encryption.BytesToPrivateKey(privkfs_raw)

	ln, err := net.Listen("tcp", "localhost:"+port)
	if err != nil {
		log.Fatalf("fail to bind port %v", port)
	}
	log.Printf("Receiver Server Listening on " + ln.Addr().String())

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal("listen accept failed", err)
		}
		go func(conn net.Conn, privK rsa.PrivateKey) {
			defer conn.Close()
			r := bufio.NewReader(conn)
			encrypted_data := make([]byte, 300)
			n, _ := r.Read(encrypted_data)
			encrypted_data = encrypted_data[0:n]

			plaintext := encryption.DecryptWithPrivateKey(encrypted_data, &privK)
			file, err := os.OpenFile("./receive", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0777)
			if err != nil {
				log.Fatal("fail to create file ./receive")
			}
			file.Write(append([]byte(hex.EncodeToString(plaintext)), []byte("\n")...))

			fmt.Println(string(plaintext))
		}(conn, *privK)
	}
}

func init() {
	rootCmd.AddCommand(setupreceiverCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// setupreceiverCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// setupreceiverCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	setupreceiverCmd.Flags().StringP("privk-file", "", "", "specify the private file using for decrypt")
	setupreceiverCmd.Flags().StringP("listen-port", "", "", "giving the port which server listen on")

	setupreceiverCmd.MarkFlagRequired("privk-file")
	setupreceiverCmd.MarkFlagRequired("listen-port")
}
