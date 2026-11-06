package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

func serverCommand(ctx context.Context, args ...string) *exec.Cmd {
	if instance := os.Getenv("FIXTURE_SERVER_INSTANCE"); instance != "" {
		args = append(args, "-socketPath", filepath.Join("/test/run", instance, "api.sock"))
	}
	cmd := exec.CommandContext(ctx, "/opt/spire/bin/spire-server", args...)
	cmd.Stderr = os.Stderr
	return cmd
}
