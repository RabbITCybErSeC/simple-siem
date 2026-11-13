package database

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestOpenErrorKeepsUsernameWithoutPassword(t *testing.T) {
	databaseURL := "postgres://postgres@127.0.0.1:1/test?sslmode=disable"
	original := fmt.Errorf("connect with user=postgres")

	err := openError(original, databaseURL)

	if !strings.Contains(err.Error(), "user=postgres") {
		t.Errorf("open error %q does not keep the username readable", err)
	}
}

func TestOpenErrorRedactsRawPassword(t *testing.T) {
	databaseURL := "postgres://postgres:pa%21ss@127.0.0.1:1/test?sslmode=disable"
	original := fmt.Errorf("driver echoed raw password %s", "pa%21ss")

	err := openError(original, databaseURL)

	if strings.Contains(err.Error(), "pa%21ss") {
		t.Errorf("open error contains the raw password: %v", err)
	}
}

func TestOpenErrorRedactsRawUserInfo(t *testing.T) {
	databaseURL := "postgres://postgres:pa%2fss@127.0.0.1:1/test?sslmode=disable"
	rawUserInfo := "postgres:pa%2fss"
	rawPassword := "pa%2fss"
	decodedPassword := "pa/ss"
	original := fmt.Errorf("driver echoed userinfo %s, password %s, decoded %s", rawUserInfo, rawPassword, decodedPassword)

	err := openError(original, databaseURL)

	for _, secret := range []string{rawUserInfo, rawPassword, decodedPassword} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("open error contains %q: %v", secret, err)
		}
	}
}

func TestOpenErrorRedactsEncodedUserInfo(t *testing.T) {
	password := "p@ss%word-4f7c2"
	userInfo := url.UserPassword("test_user", password).String()
	databaseURL := "postgres://" + userInfo + "@127.0.0.1:1/test?sslmode=disable"
	encodedPassword := strings.TrimPrefix(userInfo, "test_user:")

	original := fmt.Errorf("connect with %s, userinfo %s, or password %s", databaseURL, userInfo, password)
	err := openError(original, databaseURL)

	for _, secret := range []string{databaseURL, userInfo, encodedPassword, password} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("open error contains %q: %v", secret, err)
		}
	}
}
