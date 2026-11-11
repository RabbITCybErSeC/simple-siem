package version

// Set at build time with -ldflags "-X"; plain go build keeps the defaults.
var (
	Version = "dev"
	Commit  = "unknown"
)

func String() string {
	return Version + " (" + Commit + ")"
}
