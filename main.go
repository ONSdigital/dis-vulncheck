package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/ONSdigital/dis-vulncheck/config"
	"github.com/ONSdigital/dis-vulncheck/output"
	"github.com/ONSdigital/dis-vulncheck/report"
	"github.com/ONSdigital/log.go/v2/log"
	"github.com/spf13/afero"
)

func main() {
	ctx := context.Background()

	cliArgs := config.GetCliArgs()

	failures, err := run(ctx, cliArgs)
	if err != nil {
		exitWithError(ctx, cliArgs.Verbose, err)
	}

	fmt.Println("dis-vulncheck scan complete! 🚀")

	if failures > 0 {
		os.Exit(1)
	}

	os.Exit(0)
}

func run(ctx context.Context, cliArgs *config.CliArgs) (int, error) {
	if !cliArgs.Verbose {
		log.SetDestination(io.Discard, io.Discard)
		defer func() {
			log.SetDestination(os.Stdout, os.Stderr)
		}()
	}

	log.Info(ctx, "running dis-vulncheck")

	fs := afero.NewOsFs()

	cfg, err := config.Get(ctx, cliArgs, fs)
	if err != nil {
		log.Error(ctx, "unable to load config", err)
		return 0, fmt.Errorf("unable to load config: %v", err)
	}

	log.Info(ctx, "configuration set", log.Data{
		"config": cfg,
	})

	vulnerabilityReport, err := report.Generate(ctx, cfg)
	if err != nil {
		log.Error(ctx, "unable to generate report", err)
		return 0, fmt.Errorf("unable to generate report: %v", err)
	}

	textReport := vulnerabilityReport.GetTextReport(ctx)

	fmt.Println(textReport)

	log.Info(ctx, "complete", log.Data{
		"output": vulnerabilityReport,
	})

	return vulnerabilityReport.Results.Failures, nil
}

// exitWithError prints errors to the command line when the tool has failed to execute
func exitWithError(ctx context.Context, verbose bool, err error) {
	output.Error("dis-vulncheck has experienced an unexpected error")
	fmt.Printf("Error was: %s\n", err.Error())
	if !verbose {
		output.Error("run again in verbose mode (--verbose) for more details")
	}
	os.Exit(1)
}
