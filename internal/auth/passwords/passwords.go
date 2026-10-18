package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength     = 128
	saltLength    = 16
	memoryKiB     = 19 * 1024
	iterations    = 2
	parallelism   = 1
	derivedLength = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey([]byte(password), salt, iterations, memoryKiB, parallelism, derivedLength)
	return encodeArgon2idHash(argon2idHash{
		version:     argon2.Version,
		memoryKiB:   memoryKiB,
		iterations:  iterations,
		parallelism: parallelism,
		salt:        salt,
		derivedKey:  derivedKey,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	if expectedHash, ok := decodeLegacyHash(encodedHash); ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}
	parsedHash, ok := parseArgon2idHash(encodedHash)
	if !ok || parsedHash.version != argon2.Version {
		return false
	}
	candidate := argon2.IDKey(
		[]byte(password),
		parsedHash.salt,
		parsedHash.iterations,
		parsedHash.memoryKiB,
		parsedHash.parallelism,
		uint32(len(parsedHash.derivedKey)),
	)
	return subtle.ConstantTimeCompare(candidate, parsedHash.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
	if _, ok := decodeLegacyHash(encodedHash); ok {
		return true
	}
	parsedHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	if parsedHash.version != argon2.Version ||
		parsedHash.memoryKiB != memoryKiB ||
		parsedHash.iterations != iterations ||
		parsedHash.parallelism != parallelism ||
		len(parsedHash.derivedKey) != derivedLength {
		return true
	}
	return false
}
