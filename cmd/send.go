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
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/p1nant0m/apollo/kdc/encryption"
	"github.com/p1nant0m/apollo/utils"
	"github.com/spf13/cobra"
)

// sendCmd represents the send command
var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "send message to remote server",
	Long:  `sending encrypted to remote server`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("send called")
		processSend(cmd.Flag("sending-file").Value.String(), cmd.Flag("remote-info").Value.String())
	},
}

func processSend(fileSent string, remoteSfs string) {
	dataSent, err := ioutil.ReadFile(fileSent)
	if err != nil {
		log.Fatalf("reading from %v fails", fileSent)
	}

	targetS, err := ioutil.ReadFile(remoteSfs)
	if err != nil {
		log.Fatalf("reading from %v fails", remoteSfs)
	}

	remote_Addr := string(utils.Unpadding(targetS[0:20]))
	remote_Port := string(utils.Unpadding(targetS[20:25]))
	log.Printf("remote server: %v:%v", remote_Addr, remote_Port)
	publicK := encryption.BytesToPublicKey(targetS[25:])

	log.Printf("Plaintext: %v", string(dataSent))
	encrypted_data := encryption.EncryptWithPublicKey(dataSent, publicK)

	conn, err := net.Dial("tcp", remote_Addr+":"+remote_Port)
	if err != nil {
		log.Fatal("connect to TCP server failed", err)
	}
	defer conn.Close()

	_, err = conn.Write(encrypted_data)
	if err != nil {
		log.Fatal("fail to write encrypted data into channel", err)
	}
}

func init() {
	rootCmd.AddCommand(sendCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// sendCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// sendCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	sendCmd.Flags().StringP("sending-file", "s", "", "specify the file you want to sent to remote server")
	sendCmd.Flags().StringP("remote-info", "r", "", "specify the file you retrieve in getremote command")

	sendCmd.MarkFlagRequired("sending-file")
	sendCmd.MarkFlagRequired("remote-info")
}
