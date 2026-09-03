package main

// Negative control. Mentions algorithms in prose and identifiers only.
// We removed md5 and des usage from this package in 2021.

const (
	rsaMinBits   = 2048
	aesKeyEnvVar = "APP_AES_KEY"
)

func policy() string {
	return "Reject RSA below 2048; DES and RC4 are not permitted."
}

func describe(name string) string {
	return "configured digest: " + name
}

func addresses(in []string) []string {
	return in
}
