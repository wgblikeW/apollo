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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/p1nant0m/apollo/kdc/encryption"
	"github.com/spf13/cobra"
)

// getremoteCmd represents the getremote command
var getremoteCmd = &cobra.Command{
	Use:   "getremote",
	Short: "Get Remote Server Configuration, and prepare for communicating with it",
	Long: `getremote retrieve network address and public key of remote server that this client want to 
	communicate with`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("getremote called")
		processGetRemote(cmd.Flag("kdcaddr").Value.String(),
			cmd.Flag("kdcport").Value.String(),
			cmd.Flag("cn").Value.String(),
			cmd.Flag("privk-file").Value.String(),
			cmd.Flag("remote-server").Value.String(),
			cmd.Flag("file-saving").Value.String())
	},
}

func sign(privK *rsa.PrivateKey, msg []byte) ([]byte, error) {
	signature, err := rsa.SignPSS(rand.Reader, privK, crypto.SHA256, msg, nil)
	if err != nil {
		log.Fatal("error occurs when sign the hashed msg", err)
	}
	return signature, nil
}

func processGetRemote(KDCAddress string, KDCPort string, clientName string, privkFile string,
	remoteServer string, filename string) {
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

	// retriving privkey from file
	buf, _ := ioutil.ReadFile(privkFile)
	privk := encryption.BytesToPrivateKey(buf)

	// using RSA Signatures to Sign hashing clientname
	h := sha256.New()
	_, err = h.Write([]byte(clientName))
	if err != nil {
		log.Fatal("error occurs when hashing msg", err)
	}
	clientName_hashing := h.Sum(nil)[:10]
	h.Reset()
	h.Write([]byte(hex.EncodeToString(clientName_hashing)[0:10]))
	signature, _ := sign(privk, h.Sum(nil))

	// get hashing targetClientName
	h.Reset()
	_, err = h.Write([]byte(remoteServer))
	if err != nil {
		log.Fatal("error occurs when hashing msg", err)
	}
	remoteServer_hashing := h.Sum(nil)[:10]

	// constructing request data
	request := append([]byte{}, []byte("\x02")...)
	request = append(request, []byte(hex.EncodeToString(clientName_hashing)[0:10])...)
	request = append(request, []byte(hex.EncodeToString(remoteServer_hashing)[0:10])...)
	request = append(request, signature...)

	// sending data to KDC
	n, err := conn.Write(request)
	if err != nil {
		log.Println("error in writing to connection channel", n, err)
		return
	}

	buf = make([]byte, 3000)
	n, err = conn.Read(buf)
	if err != nil {
		log.Println("error in reading connection channel", n, err)
		return
	}
	status := buf[0]

	if status == byte(0) {
		log.Println("fail to receive remote server info")
		return
	} else {
		log.Println("successfully receive remote server info")
	}
	data := buf[1:n]

	// writing remote server info to file
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0700)
	if err != nil {
		log.Println("error in opening/creating file", filename, err)
		return
	}
	defer file.Close()
	file.Write(data[0:n])
}

func init() {
	rootCmd.AddCommand(getremoteCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// getremoteCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// getremoteCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	getremoteCmd.Flags().StringP("privk-file", "p", "", "specify a private key file")
	getremoteCmd.Flags().StringP("remote-server", "r", "", "giving remote server name that you want to communicate")
	getremoteCmd.Flags().StringP("file-saving", "f", "./remote_server", "file path you want to keep remote server info")
	getremoteCmd.Flags().StringP("kdcaddr", "", "127.0.0.1", "KDC Server IP Address")
	getremoteCmd.Flags().StringP("kdcport", "", "443", "KDC Server listented port")
	getremoteCmd.Flags().StringP("cn", "", "", "Client Server identification")

	// getremoteCmd.MarkFlagRequired("kdcaddr")
	// getremoteCmd.MarkFlagRequired("kdcport")
	getremoteCmd.MarkFlagRequired("cn")
	getremoteCmd.MarkFlagRequired("privk-file")
	getremoteCmd.MarkFlagRequired("remote-server")
}
