package main

import (
	"crypto/aes"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func weakKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024)
}

func standardKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func ecKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func tripleDes(key []byte) {
	_, _ = des.NewTripleDESCipher(key)
}

func block(key []byte) {
	_, _ = aes.NewCipher(key)
}

func digests(b []byte) {
	_ = md5.Sum(b)
	_ = sha256.Sum256(b)
}
