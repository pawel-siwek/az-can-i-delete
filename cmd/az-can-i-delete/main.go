// Command az-can-i-delete reports evidence before Azure infrastructure deletion.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/pawel-siwek/az-can-i-delete/internal/cli"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version)
}
