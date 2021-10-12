package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
	"os"
)

func EncryptFile(targetFilename string, key []byte) string {
	infile, err := os.Open(targetFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer infile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}

	nonce := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}
	outfileName := setFilename(targetFilename, "encrypt")
	outfile, err := os.OpenFile(outfileName, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()

	// The buffer size must be multiple of 16 bytes
	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, nonce)
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			// Write into file
			outfile.Write(buf[:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Printf("Read %d bytes: %v", n, err)
			break
		}
	}
	// Append the nonce
	outfile.Write(nonce)
	return outfileName
}
