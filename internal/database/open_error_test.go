package database

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

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
