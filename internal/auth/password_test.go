package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

const validPassword = "correct horse battery staple"

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"11 runes", strings.Repeat("a", 11), true},
		{"12 runes", strings.Repeat("a", 12), false},
		{"128 runes", strings.Repeat("a", 128), false},
		{"129 runes", strings.Repeat("a", 129), true},
		{"11 multibyte runes", strings.Repeat("é", 11), true},
		{"12 multibyte runes", strings.Repeat("é", 12), false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePassword(test.password)
			if test.wantErr {
				if !errors.Is(err, ErrPasswordLength) {
					t.Errorf("ValidatePassword(%d runes) = %v, want ErrPasswordLength", len([]rune(test.password)), err)
				}
				return
			}
			if err != nil {
				t.Errorf("ValidatePassword(%d runes) = %v, want nil", len([]rune(test.password)), err)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	const prefix = "$argon2id$v=19$m=19456,t=2,p=1$"

	first, err := HashPassword(context.Background(), validPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(first, prefix) {
		t.Errorf("HashPassword output %q does not start with %q", first, prefix)
	}
	if strings.Contains(first, validPassword) {
		t.Errorf("HashPassword output contains the password: %q", first)
	}

	second, err := HashPassword(context.Background(), validPassword)
	if err != nil {
		t.Fatalf("second HashPassword: %v", err)
	}
	if first == second {
		t.Error("two hashes of the same password are equal, want random salts")
	}
}

func TestVerifyPassword(t *testing.T) {
	encoded, err := HashPassword(context.Background(), validPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	matches, err := VerifyPassword(context.Background(), validPassword, encoded)
	if err != nil {
		t.Fatalf("VerifyPassword with the right password: %v", err)
	}
	if !matches {
		t.Error("VerifyPassword with the right password = false, want true")
	}

	matches, err = VerifyPassword(context.Background(), "wrong password", encoded)
	if err != nil {
		t.Fatalf("VerifyPassword with a wrong password: %v", err)
	}
	if matches {
		t.Error("VerifyPassword with a wrong password = true, want false")
	}
}

func TestVerifyPasswordRejectsMalformedHashes(t *testing.T) {
	encoded, err := HashPassword(context.Background(), validPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("HashPassword output %q has %d PHC parts, want 6", encoded, len(parts))
	}

	tests := []struct {
		name    string
		encoded string
	}{
		{"empty", ""},
		{"missing parts", "$argon2id$v=19$m=x"},
		{"wrong version", strings.Replace(encoded, "v=19", "v=16", 1)},
		{"non-numeric parameters", strings.Replace(encoded, "m=19456", "m=many", 1)},
		{"bad salt base64", withPart(parts, 4, "not*base64")},
		{"bad key base64", withPart(parts, 5, "not*base64")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches, err := VerifyPassword(context.Background(), validPassword, test.encoded)
			if matches {
				t.Errorf("VerifyPassword(%q) = true, want false", test.encoded)
			}
			if err == nil {
				t.Errorf("VerifyPassword(%q) returned no error", test.encoded)
			}
		})
	}
}

func TestNeedsRehash(t *testing.T) {
	fresh, err := HashPassword(context.Background(), validPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if needsRehash(fresh) {
		t.Error("needsRehash(fresh hash) = true, want false")
	}

	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	key := argon2.IDKey([]byte(validPassword), salt, 1, argonMemory, argonThreads, keyLength)
	old := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		1,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	if !needsRehash(old) {
		t.Error("needsRehash(hash with t=1) = false, want true")
	}
}

func TestHashPasswordHonorsCanceledContextWhileWaiting(t *testing.T) {
	fillHashSlots(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := HashPassword(ctx, validPassword)
	if !errors.Is(err, ctx.Err()) {
		t.Errorf("HashPassword with a canceled context = %v, want %v", err, ctx.Err())
	}
}

func TestHashPasswordWaitsForASlot(t *testing.T) {
	fillHashSlots(t)
	type hashResult struct {
		hash string
		err  error
	}
	result := make(chan hashResult, 1)

	go func() {
		hash, err := HashPassword(context.Background(), validPassword)
		result <- hashResult{hash: hash, err: err}
	}()

	select {
	case got := <-result:
		t.Fatalf("HashPassword returned before a slot was free: hash=%q err=%v", got.hash, got.err)
	case <-time.After(50 * time.Millisecond):
	}

	<-hashSlots

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("HashPassword after a slot was freed: %v", got.err)
		}
		if !strings.HasPrefix(got.hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
			t.Errorf("HashPassword after a slot was freed returned %q", got.hash)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HashPassword did not return after a slot was freed")
	}
}

// fillHashSlots takes every hash slot and releases them when the test ends.
func fillHashSlots(t *testing.T) {
	t.Helper()
	for range maxConcurrentHashes {
		hashSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for range maxConcurrentHashes {
			select {
			case <-hashSlots:
			default:
				return
			}
		}
	})
}

func withPart(parts []string, index int, value string) string {
	replaced := append([]string(nil), parts...)
	replaced[index] = value
	return strings.Join(replaced, "$")
}
