//go:build darwin && amd64

package anchor

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	pb "github.com/veil-net/conflux/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

//go:embed bin/anchor-darwin-10.12-amd64
var anchorPlugin []byte

func NewAnchor() (pb.AnchorClient, *exec.Cmd, error) {
	// Extract the embedded file to a temporary directory
	pluginPath := filepath.Join(os.TempDir(), "anchor")
	// Remove existing file if it exists to avoid "text file busy" error
	os.Remove(pluginPath)
	if err := os.WriteFile(pluginPath, anchorPlugin, 0755); err != nil {
		return nil, nil, err
	}

	// Start the anchor binary as a manageable subprocess (runs the gRPC server)
	cmd := exec.Command(pluginPath)
	// Link stdout and stderr to see logs from the subprocess
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	// Verify the process started successfully
	if cmd.Process == nil {
		return nil, nil, exec.ErrNotFound
	}

	time.Sleep(1 * time.Second)

	// Create a gRPC client connection
	conn, err := grpc.NewClient("127.0.0.1:1993", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}

	client := pb.NewAnchorClient(conn)
	return client, cmd, nil
}
