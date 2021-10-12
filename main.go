package main

import (
	"flag"
	"log"
	"strings"

	"github.com/go-piv/piv-go/piv"
)

func main() {
	setupFlag := flag.Bool("setup", false, "setup: configure a new YubiKey")
	encryptFlag := flag.Bool("encrypt", false, "encrypt: encrypt some file")
	fileNameFlag := flag.String("filename", "", "filename: file to encrypt or decrypt")
	decryptFlag := flag.Bool("decrypt", false, "decrypt: decrypt some file")
	flag.Parse()

	yk := connect()
	core := &Core{}
	core.YK = yk

	if *setupFlag {
		log.SetFlags(0)

		pin := setPinPrompt()
		core.Pin = pin

		core.setPinToYubiKey()
		core.generateKeyPair()
		log.Println("Yubikey Setup Successfully")
	} else {
		pin := getPINPrompt()
		core.Pin = pin

		core.AuthenticatePin()
		log.Println("Yubikey Configuration Authenticated")
	}

	core.GetECDSAPublicKey()
	core.GetPrivateKey()

	if err := checkObjects(core); err != nil {
		log.Fatal(err)
	}

	if *encryptFlag {
		if err := ensureYK(core.YK); err != nil {
			log.Fatal("Need Keep YubiKey inserted")
		}

		if fileNameFlag == nil {
			log.Fatal("Must specify a file name")
		}

		AESKey := core.GenerateAESKey()

		filename := EncryptFile(*fileNameFlag, AESKey)
		log.Println("Yubikey File Encryted Successfully")
		log.Println(filename)
	}

	if *decryptFlag {
		if err := ensureYK(core.YK); err != nil {
			log.Fatal("Need Keep YubiKey inserted")
		}

		if fileNameFlag == nil {
			log.Fatal("Must specify a file name")
		}

		AESKey := core.GenerateAESKey()
		filename := DecryptFile(*fileNameFlag, AESKey)
		log.Println("Yubikey File Decryted Successfully")
		log.Println(filename)
	}
}

func connect() *piv.YubiKey {
	// List all smartCards connected to the system.
	cards, err := piv.Cards()
	if err != nil {
		log.Fatalln("Failed to enumerate tokens:", err)
	}

	if len(cards) == 0 {
		log.Fatalln("No YubiKeys detected!")
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if tx, err := piv.Open(card); err != nil {
				log.Fatalln("Failed to connect to the YubiKey:", err)
			} else {
				yk = tx
			}
			break
		}
	}
	return yk
}
