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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/p1nant0m/apollo/utils"
	"github.com/spf13/cobra"
)

// registCmd represents the regist command
var registCmd = &cobra.Command{
	Use:   "regist",
	Short: "Regist make this server regist to remote KDC and retrieve key.",
	Long: `Regist do regist this server to remote Key Distribution Center, and retrieve
	Private Key. You can specify a saving path for private key using flag [-f]. This procedure
	makes discovery possible to other server who wants to communicate with you via encryption
	channel.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("regist called")
		processRegist(
			cmd.Flag("kdc-address").Value.String(),
			cmd.Flag("kdc-listen-port").Value.String(),
			cmd.Flag("receiver-addr").Value.String(),
			cmd.Flag("receiver-port").Value.String(),
			cmd.Flag("file-saving").Value.String(),
			cmd.Flag("client-name").Value.String())
	},
}

//
// processRegist connects to remote KDC via TCP channel under TLS
// and sends customized protocol package to regist in KDC
//
func processRegist(KDCAddress string, KDCPort string, receiverAddr string,
	receiverPort string, filename string, clientName string) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	// connecting to KDC under TLS
	conn, err := tls.Dial("tcp", KDCAddress+":"+KDCPort, conf)
	if err != nil {
		log.Println("Connecting to"+KDCAddress+":"+KDCPort+"fails", err)
		return
	}
	defer conn.Close()

	// constructing request data
	h := sha256.New()
	h.Write([]byte(clientName))
	clientName_byte := h.Sum(nil)[0:10]
	clientName_Hex_byte := []byte(hex.EncodeToString(clientName_byte)[0:10])
	padding_receiverAddr, _ := utils.Padding([]byte(receiverAddr), 20)
	padding_receiverPort, _ := utils.Padding([]byte(receiverPort), 5)

	request := append([]byte{}, []byte("\x01")...)
	request = append(request, clientName_Hex_byte...)
	request = append(request, padding_receiverAddr...)
	request = append(request, padding_receiverPort...)
	request = append(request, []byte("\x00")...)

	// sending data to KDC
	n, err := conn.Write(request)
	if err != nil {
		log.Println("error in writing to connection channel", n, err)
		return
	}

	buf := make([]byte, 3000)
	n, err = conn.Read(buf)
	if err != nil {
		log.Println("error in reading connection channel", n, err)
		return
	}

	// writing private key to file
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0700)
	if err != nil {
		log.Println("error in opening/creating file", filename, err)
		return
	}
	defer file.Close()
	file.Write(buf[0:n])

}

func init() {
	rootCmd.AddCommand(registCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// registCmd.PersistentFlags().String("foo", "", "A help for foo")

	// registCmd.PersistentFlags().StringP("kdc-address", "k", "127.0.0.1", "KDC Server IP Address")
	// registCmd.PersistentFlags().StringP("kdc-listen-port", "l", "7070", "KDC Server listented port")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// registCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	registCmd.Flags().StringP("file-saving", "f", "./privateKey.key", "path you want to keep file")
	registCmd.Flags().StringP("receiver-addr", "t", "", "Message Receiver IP Address")
	registCmd.Flags().StringP("receiver-port", "p", "", "Message Receiver Listening Port")
	registCmd.Flags().StringP("client-name", "n", "", "Client Server identification")
	registCmd.Flags().StringP("kdc-address", "k", "127.0.0.1", "KDC Server IP Address")
	registCmd.Flags().StringP("kdc-listen-port", "l", "7070", "KDC Server listented port")

	registCmd.MarkFlagRequired("kdc-address")
	registCmd.MarkFlagRequired("kdc-listen-port")
	registCmd.MarkFlagRequired("receiver-addr")
	registCmd.MarkFlagRequired("receiver-port")
	registCmd.MarkFlagRequired("client-name")
}
