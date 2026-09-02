package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/osbuild/logging/pkg/sinit"
)

func main() {
	ctx, applicationCancel := context.WithCancel(context.Background())
	defer applicationCancel()

	terminationSignal := make(chan os.Signal, 1)
	signal.Notify(terminationSignal, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(terminationSignal)

	// Channel to track graceful application shutdown
	shutdownSignal := make(chan struct{})

	go func() {
		select {
		case <-terminationSignal:
			fmt.Println("Received termination signal, cancelling context...")
			applicationCancel()
		case <-shutdownSignal:
			// Normal application shutdown, no logging
		}
	}()

	ctx, cancelTimeout := context.WithTimeout(ctx, 2*time.Hour)
	defer cancelTimeout()

	conf := Config{
		DryRun:                  true,
		EnableDBMaintenance:     false,
		EnableBlueprintSplit:    false,
		ComposesRetentionMonths: 24,
	}

	err := LoadConfigFromEnv(&conf)
	if err != nil {
		panic(err)
	}

	loggingConfig := sinit.LoggingConfig{
		StdoutConfig: sinit.StdoutConfig{
			Enabled: true,
			Level:   "debug",
			Format:  "text",
		},
	}

	err = sinit.InitializeLogging(ctx, loggingConfig)
	if err != nil {
		panic(err)
	}

	slog.InfoContext(ctx, "starting image-builder maintainance")

	if conf.DryRun {
		slog.InfoContext(ctx, "dry run, no state will be changed")
	}

	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		conf.PGUser,
		conf.PGPassword,
		conf.PGHost,
		conf.PGPort,
		conf.PGDatabase,
		conf.PGSSLMode,
	)

	failed := false
	if !conf.EnableDBMaintenance {
		slog.InfoContext(ctx, "🦀🦀🦀 DB maintenance not enabled, skipping  🦀🦀🦀")
	} else {
		err = DBCleanup(ctx, dbURL, conf.DryRun, conf.ComposesRetentionMonths)
		if err != nil {
			slog.ErrorContext(ctx, "error during DBCleanup", "err", err)
			failed = true
		} else {
			slog.InfoContext(ctx, "🦀🦀🦀 dbqueue cleanup done 🦀🦀🦀")
		}
	}

	if !conf.EnableBlueprintSplit {
		slog.InfoContext(ctx, "🦀🦀🦀 blueprint split not enabled, skipping 🦀🦀🦀")
	} else {
		err = SplitMultiTargetBlueprints(ctx, dbURL, conf.DryRun)
		if err != nil {
			slog.ErrorContext(ctx, "error during blueprint split", "err", err)
			failed = true
		} else {
			slog.InfoContext(ctx, "🦀🦀🦀 blueprint split done 🦀🦀🦀")
		}
	}

	if failed {
		os.Exit(1)
	}
	close(shutdownSignal)
}
