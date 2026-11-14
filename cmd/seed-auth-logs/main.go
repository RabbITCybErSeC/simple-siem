package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/devdata"
)

const (
	requestTimeout = time.Minute

	usage = `usage: seed-auth-logs [flags]

Writes a reproducible auth-log dataset to a development Elasticsearch.
Credentials come from ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD.`
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("seed-auth-logs", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { _, _ = fmt.Fprintln(stderr, usage) }

	urlFlag := flags.String("url", getenv("ELASTICSEARCH_URL"), "Elasticsearch URL (default $ELASTICSEARCH_URL)")
	seed := flags.Int64("seed", 1, "dataset seed")
	endFlag := flags.String("end", "", "RFC 3339 end of the window (default now, truncated to the minute)")
	indexPrefix := flags.String("index-prefix", "auth", "index name prefix")
	background := flags.Int("background", 200, "number of background events")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		flags.Usage()
		return 2
	}
	if *urlFlag == "" {
		_, _ = fmt.Fprintln(stderr, "missing Elasticsearch URL: set --url or ELASTICSEARCH_URL")
		return 2
	}

	end := time.Now().UTC().Truncate(time.Minute)
	if *endFlag != "" {
		parsedEnd, err := time.Parse(time.RFC3339, *endFlag)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "invalid --end: %v\n", err)
			return 2
		}
		end = parsedEnd.UTC()
	}

	options := devdata.Options{
		Seed:        *seed,
		End:         end,
		IndexPrefix: *indexPrefix,
		Background:  *background,
	}
	documents := devdata.GenerateAuthLogs(options)
	writer := &devdata.Writer{
		URL:      *urlFlag,
		Username: getenv("ELASTICSEARCH_USERNAME"),
		Password: getenv("ELASTICSEARCH_PASSWORD"),
		Client:   &http.Client{Timeout: requestTimeout},
	}

	if err := writer.PutIndexTemplate(ctx, *indexPrefix); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	counts, err := writer.Write(ctx, documents)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	printSummary(stdout, documents, counts)
	return 0
}

// printSummary prints one line per index, then the scenario counts.
func printSummary(stdout io.Writer, documents []devdata.Document, counts map[string]int) {
	for _, index := range slices.Sorted(maps.Keys(counts)) {
		_, _ = fmt.Fprintf(stdout, "index %s: %d documents\n", index, counts[index])
	}

	scenarioCounts := map[string]int{}
	for _, document := range documents {
		scenarioCounts[document.Scenario]++
	}
	for _, scenario := range slices.Sorted(maps.Keys(scenarioCounts)) {
		_, _ = fmt.Fprintf(stdout, "scenario %s: %d documents\n", scenario, scenarioCounts[scenario])
	}
	_, _ = fmt.Fprintf(stdout, "total: %d documents\n", len(documents))
}
