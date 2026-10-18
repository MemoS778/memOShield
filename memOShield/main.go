package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/MemoS778/memOShield/internal/personal"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := personal.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
