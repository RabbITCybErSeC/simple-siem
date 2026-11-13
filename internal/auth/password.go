package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory         = 19 * 1024
	argonTime           = 2
	argonThreads        = 1
	saltLength          = 16
	keyLength           = 32
	maxConcurrentHashes = 4
)

var (
	errMalformedHash = errors.New("malformed password hash")
	hashSlots        = make(chan struct{}, maxConcurrentHashes)
)

// hashParameters is the parsed form of an Argon2id PHC string.
type hashParameters struct {
	memory   uint32
	timeCost uint32
	threads  uint8
	salt     []byte
	key      []byte
}

// ValidatePassword reports whether password is 12 to 128 runes long.
func ValidatePassword(password string) error {
	length := utf8.RuneCountInString(password)
	if length < 12 || length > 128 {
		return ErrPasswordLength
	}
	return nil
}

// HashPassword encodes password as an Argon2id PHC string.
func HashPassword(ctx context.Context, password string) (string, error) {
	release, err := acquireHashSlot(ctx)
	if err != nil {
		return "", err
	}
	defer release()

	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLength)
	return encodeHash(salt, key, argonMemory, argonTime, argonThreads), nil
}

// VerifyPassword reports whether password matches the encoded Argon2id hash.
func VerifyPassword(ctx context.Context, password, encoded string) (bool, error) {
	release, err := acquireHashSlot(ctx)
	if err != nil {
		return false, err
	}
	defer release()

	parameters, err := parseHash(encoded)
	if err != nil {
		return false, err
	}
	key := argon2.IDKey(
		[]byte(password),
		parameters.salt,
		parameters.timeCost,
		parameters.memory,
		parameters.threads,
		uint32(len(parameters.key)),
	)
	return subtle.ConstantTimeCompare(key, parameters.key) == 1, nil
}

// needsRehash reports whether encoded was made with different parameters.
func needsRehash(encoded string) bool {
	parameters, err := parseHash(encoded)
	if err != nil {
		return true
	}
	return parameters.memory != argonMemory ||
		parameters.timeCost != argonTime ||
		parameters.threads != argonThreads ||
		len(parameters.salt) != saltLength ||
		len(parameters.key) != keyLength
}

func encodeHash(salt, key []byte, memory, timeCost uint32, threads uint8) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memory,
		timeCost,
		threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func parseHash(encoded string) (hashParameters, error) {
	fields := strings.Split(encoded, "$")
	if len(fields) != 6 || fields[0] != "" || fields[1] != "argon2id" {
		return hashParameters{}, errMalformedHash
	}

	version, found := strings.CutPrefix(fields[2], "v=")
	if !found {
		return hashParameters{}, errMalformedHash
	}
	parsedVersion, err := strconv.ParseUint(version, 10, 32)
	if err != nil || parsedVersion != argon2.Version {
		return hashParameters{}, errMalformedHash
	}

	parameterFields := strings.Split(fields[3], ",")
	if len(parameterFields) != 3 {
		return hashParameters{}, errMalformedHash
	}
	var parameters hashParameters
	for _, parameter := range parameterFields {
		name, value, found := strings.Cut(parameter, "=")
		if !found {
			return hashParameters{}, errMalformedHash
		}
		switch name {
		case "m":
			memory, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return hashParameters{}, errMalformedHash
			}
			parameters.memory = uint32(memory)
		case "t":
			timeCost, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return hashParameters{}, errMalformedHash
			}
			parameters.timeCost = uint32(timeCost)
		case "p":
			threads, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return hashParameters{}, errMalformedHash
			}
			parameters.threads = uint8(threads)
		default:
			return hashParameters{}, errMalformedHash
		}
	}
	if parameters.memory == 0 || parameters.timeCost == 0 || parameters.threads == 0 {
		return hashParameters{}, errMalformedHash
	}

	parameters.salt, err = base64.RawStdEncoding.DecodeString(fields[4])
	if err != nil {
		return hashParameters{}, errMalformedHash
	}
	parameters.key, err = base64.RawStdEncoding.DecodeString(fields[5])
	if err != nil {
		return hashParameters{}, errMalformedHash
	}
	if len(parameters.salt) == 0 || len(parameters.key) == 0 {
		return hashParameters{}, errMalformedHash
	}
	return parameters, nil
}

// acquireHashSlot waits for one of the hash slots or for ctx to end.
func acquireHashSlot(ctx context.Context) (func(), error) {
	select {
	case hashSlots <- struct{}{}:
		return func() { <-hashSlots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
