package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/term"
)

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalln("Failed to generate serial number:", err)
	}
	return serialNumber
}

func ensureYK(yk *piv.YubiKey) error {
	_, err := yk.AttestationCertificate()
	healthy := err == nil
	if yk == nil || !healthy {
		if yk != nil {
			log.Println("Reconnecting to the YubiKey...")
			yk.Close()
		} else {
			log.Println("Connecting to the YubiKey...")
		}
	}
	return nil
}

func getPINPrompt() []byte {
	fmt.Print("Input your PIN/PUK: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}
	if len(pin) != 8 {
		log.Fatalln("The PIN needs to be 8 characters.")
	}

	return pin
}

func setPinPrompt() []byte {

	fmt.Print("Choose a new 8bit PIN/PUK: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}
	if len(pin) != 8 {
		log.Fatalln("The PIN needs to be 8 characters.")
	}
	fmt.Print("Repeat PIN/PUK: ")
	repeat, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	} else if !bytes.Equal(repeat, pin) {
		log.Fatalln("PINs don't match!")
	}
	return pin
}

func checkObjects(core *Core) error {
	if core.Pub == nil {
		return errors.New("ECDSA Public Key Empty")
	}
	if core.Priv == nil {
		return errors.New("YubiKey ECDSA Private Key Empty")
	}
	if core.OriginPriv == nil {
		return errors.New("origin Private Key Empty")
	}
	if core.OriginPub == nil {
		return errors.New("origin Public Key Empty")
	}
	if core.YK == nil {
		return errors.New("yubikey engine empty")
	}
	if core.ManagementKey[:] == nil {
		return errors.New("management key empty")
	}
	if core.Pin == nil {
		return errors.New("pin empty")
	}
	return nil
}

func setFilename(targetFilename string, pattern string) string {
	var outfileName string
	switch pattern {
	case "decrypt":
		realfileName := strings.ReplaceAll(targetFilename, "_encrypted.bin", "")
		withoutExtension := strings.TrimSuffix(realfileName, filepath.Ext(realfileName))
		outfileName = strings.ReplaceAll(realfileName, withoutExtension, withoutExtension+"_decrypted")
		log.Println(outfileName)
	case "encrypt":
		outfileName = targetFilename + "_encrypted" + ".bin"
	}
	return outfileName
}
