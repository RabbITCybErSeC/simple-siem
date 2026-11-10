package version

import "testing"

func TestStringShowsVersionAndCommit(t *testing.T) {
	previousVersion := Version
	previousCommit := Commit
	Version = "v1.2.3"
	Commit = "abc1234"
	t.Cleanup(func() {
		Version = previousVersion
		Commit = previousCommit
	})

	if got, want := String(), "v1.2.3 (abc1234)"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestStringDefaultsToDevAndUnknown(t *testing.T) {
	if got, want := String(), "dev (unknown)"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
