package main

import (
	"fmt"
	"io"
	"os"

	"github.com/RabbITCybErSeC/simple-siem/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] != "version" {
		_, _ = fmt.Fprintln(stderr, "usage: simple-siem [version]")
		return 2
	}

	_, _ = fmt.Fprintf(stdout, "simple-siem %s\n", version.String())
	return 0
}
