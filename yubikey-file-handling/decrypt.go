package main

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"log"
	"os"
)

func DecryptFile(targetFilename string, key []byte) string {
	infile, err := os.Open(targetFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer infile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}

	fi, err := infile.Stat()
	if err != nil {
		log.Fatal(err)
	}

	nonce := make([]byte, block.BlockSize())
	msgLen := fi.Size() - int64(len(nonce))
	_, err = infile.ReadAt(nonce, msgLen)
	if err != nil {
		log.Fatal(err)
	}
	outfileName := setFilename(targetFilename, "decrypt")
	outfile, err := os.OpenFile(outfileName, os.O_RDWR|os.O_CREATE, 0644)
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
			// The last bytes are the nonce, don't belong the original message
			if n > int(msgLen) {
				n = int(msgLen)
			}
			msgLen -= int64(n)
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
	return outfileName
}
