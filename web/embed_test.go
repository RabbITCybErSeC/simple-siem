package web

import (
	"errors"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

var (
	scriptTagPattern          = regexp.MustCompile(`(?i)<script\b[^>]*>`)
	styleTagPattern           = regexp.MustCompile(`(?i)<style\b`)
	remoteAttributePattern    = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']?(?:https?:)?//`)
	remoteCSSReferencePattern = regexp.MustCompile(`(?i)url\(\s*["']?(?:https?:)?//`)
)

// shortcut: static scan of the build, replace with Playwright under the real CSP in Phase 2b
func TestRemoteReferencePatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern *regexp.Regexp
		text    string
		remote  bool
	}{
		{"https script", remoteAttributePattern, `<script src="https://cdn.example.com/lib.js">`, true},
		{"protocol-relative script", remoteAttributePattern, `<script src="//cdn.example.com/lib.js">`, true},
		{"local script", remoteAttributePattern, `<script src="/assets/index.js">`, false},
		{"protocol-relative font", remoteCSSReferencePattern, `url(//fonts.example.com/font.woff2)`, true},
		{"local font", remoteCSSReferencePattern, `url(/assets/font.woff2)`, false},
	}

	for _, test := range tests {
		if got := test.pattern.MatchString(test.text); got != test.remote {
			t.Errorf("%s: remote match = %v, want %v for %s", test.name, got, test.remote, test.text)
		}
	}
}

func TestBuiltFrontendIsSelfContained(t *testing.T) {
	files := Files()
	indexHTML, err := fs.ReadFile(files, "index.html")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("frontend not built")
	}
	if err != nil {
		t.Fatalf("read embedded index.html: %v", err)
	}

	for _, tag := range scriptTagPattern.FindAll(indexHTML, -1) {
		if !strings.Contains(string(tag), "src=") {
			t.Errorf("index.html has an inline script tag: %s", tag)
		}
	}
	if styleTagPattern.Match(indexHTML) {
		t.Error("index.html has a style element")
	}
	if reference := remoteAttributePattern.Find(indexHTML); reference != nil {
		t.Errorf("index.html loads a remote file: %s", reference)
	}

	err = fs.WalkDir(files, ".", func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(filePath, ".css") {
			return walkErr
		}
		stylesheet, err := fs.ReadFile(files, filePath)
		if err != nil {
			return err
		}
		if reference := remoteCSSReferencePattern.Find(stylesheet); reference != nil {
			t.Errorf("%s loads a remote file: %s", filePath, reference)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded files: %v", err)
	}
}
