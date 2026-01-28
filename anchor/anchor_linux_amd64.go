//go:build linux && amd64

package anchor

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	pb "github.com/veil-net/conflux/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

//go:embed bin/anchor-linux-amd64
var anchorPlugin []byte

func NewAnchor() (*exec.Cmd, error) {
	// Extract the embedded file to a temporary directory
	pluginPath := filepath.Join(os.TempDir(), "anchor")
	// Remove existing file if it exists to avoid "text file busy" error
	os.Remove(pluginPath)
	if err := os.WriteFile(pluginPath, anchorPlugin, 0755); err != nil {
		return nil, err
	}

	// Start the anchor binary as a manageable subprocess (runs the gRPC server)
	cmd := exec.Command(pluginPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	// Link stdout and stderr to see logs from the subprocess
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Verify the process started successfully
	if cmd.Process == nil {
		return nil, exec.ErrNotFound
	}

	return cmd, nil
}

func NewAnchorClient() (pb.AnchorClient, error) {
	// Create a gRPC client connection
	conn, err := grpc.NewClient("127.0.0.1:1993", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	client := pb.NewAnchorClient(conn)
	return client, nil
}