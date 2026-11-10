package main

import (
	"bytes"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/version"
)

func TestRun(t *testing.T) {
	previousVersion := version.Version
	previousCommit := version.Commit
	version.Version = "v1.2.3"
	version.Commit = "abc1234"
	t.Cleanup(func() {
		version.Version = previousVersion
		version.Commit = previousCommit
	})

	tests := []struct {
		name       string
		args       []string
		wantStatus int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "version argument",
			args:       []string{"version"},
			wantStatus: 0,
			wantStdout: "simple-siem v1.2.3 (abc1234)\n",
		},
		{
			name:       "no argument",
			wantStatus: 0,
			wantStdout: "simple-siem v1.2.3 (abc1234)\n",
		},
		{
			name:       "unknown argument",
			args:       []string{"serve"},
			wantStatus: 2,
			wantStderr: "usage: simple-siem [version]\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			status := run(test.args, &stdout, &stderr)

			if status != test.wantStatus {
				t.Errorf("run() status = %d, want %d", status, test.wantStatus)
			}
			if got := stdout.String(); got != test.wantStdout {
				t.Errorf("run() stdout = %q, want %q", got, test.wantStdout)
			}
			if got := stderr.String(); got != test.wantStderr {
				t.Errorf("run() stderr = %q, want %q", got, test.wantStderr)
			}
		})
	}
}
