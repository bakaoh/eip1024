package eip1024

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type Account struct {
	ethereumPrivateKey   string
	encryptionPrivateKey string
	encryptionPublicKey  string
}

type Message struct {
	data string
}

var bob = Account{
	ethereumPrivateKey:   "7e5374ec2ef0d91761a6e72fdf8f6ac665519bfdf6da0a2329cf0d804514b816",
	encryptionPrivateKey: "flN07C7w2Rdhpucv349qxmVRm/322gojKc8NgEUUuBY=",
	encryptionPublicKey:  "C5YMNdqE4kLgxQhJO1MfuQcHP5hjVSXzamzd/TxlR0U=",
}

var secretMessage = "My name is Satoshi Buterin"

func Test_GetEncryptionPublicKey(t *testing.T) {
	result := GetEncryptionPublicKey(bob.ethereumPrivateKey)
	assert.Equal(t, result, bob.encryptionPublicKey)
}

func Test_Encrypt(t *testing.T) {
	encrypted, err := Encrypt(
		bob.encryptionPublicKey,
		[]byte(secretMessage),
		"x25519-xsalsa20-poly1305",
	)
	assert.Nil(t, err)

	decrypted, err := Decrypt(bob.ethereumPrivateKey, encrypted)
	assert.Nil(t, err)
	assert.Equal(t, secretMessage, string(decrypted))
}
