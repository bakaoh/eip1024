package eip1024

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// EncryptedData is encrypted blob
type EncryptedData struct {
	Version        string
	Nonce          string
	EphemPublicKey string
	Ciphertext     string
}

// GetEncryptionPublicKey returns user's public Encryption key derived from privateKey Ethereum key
func GetEncryptionPublicKey(receiverAddress string) string {
	privateKey0, _ := hexutil.Decode("0x" + receiverAddress)
	privateKey := [32]byte{}
	copy(privateKey[:], privateKey0[:32])

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return base64.StdEncoding.EncodeToString(publicKey[:])
}

// Encrypt plain data
func Encrypt(receiverPublicKey string, data []byte, version string) (*EncryptedData, error) {
	switch version {
	case "x25519-xsalsa20-poly1305":
		ephemeralPublic, ephemeralPrivate, _ := box.GenerateKey(rand.Reader)

		publicKey0, _ := base64.StdEncoding.DecodeString(receiverPublicKey)
		publicKey := [32]byte{}
		copy(publicKey[:], publicKey0[:32])

		var nonce [24]byte
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			return nil, err
		}

		out := box.Seal(nil, data, &nonce, &publicKey, ephemeralPrivate)

		return &EncryptedData{
			Version:        version,
			Nonce:          base64.StdEncoding.EncodeToString(nonce[:]),
			EphemPublicKey: base64.StdEncoding.EncodeToString(ephemeralPublic[:]),
			Ciphertext:     base64.StdEncoding.EncodeToString(out),
		}, nil
	default:
		return nil, errors.New("Encryption type/version not supported")
	}
}

// Decrypt some encrypted data.
func Decrypt(recievierPrivatekey string, encryptedData *EncryptedData) ([]byte, error) {
	switch encryptedData.Version {
	case "x25519-xsalsa20-poly1305":
		privateKey0, _ := hexutil.Decode("0x" + recievierPrivatekey)
		privateKey := [32]byte{}
		copy(privateKey[:], privateKey0[:32])

		// assemble decryption parameters
		nonce, _ := base64.StdEncoding.DecodeString(encryptedData.Nonce)
		ciphertext, _ := base64.StdEncoding.DecodeString(encryptedData.Ciphertext)
		ephemPublicKey, _ := base64.StdEncoding.DecodeString(encryptedData.EphemPublicKey)

		publicKey := [32]byte{}
		copy(publicKey[:], ephemPublicKey[:32])

		nonce24 := [24]byte{}
		copy(nonce24[:], nonce[:24])

		decryptedMessage, _ := box.Open(nil, ciphertext, &nonce24, &publicKey, &privateKey)
		return decryptedMessage, nil
	default:
		return nil, errors.New("Encryption type/version not supported")
	}
}
