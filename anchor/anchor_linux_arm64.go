//go:build linux && arm64

package anchor

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"

	pb "github.com/veil-net/conflux/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// anchorPlugin is the embedded anchor binary for this GOOS/GOARCH.
//go:embed bin/anchor-linux-arm64
var anchorPlugin []byte

// NewAnchor extracts the embedded binary to a temp file and starts it as a subprocess (gRPC server).
//
// Inputs: none.
//
// Outputs:
//   - *exec.Cmd. The started anchor subprocess.
//   - err: error. Non-nil if the binary cannot be extracted or started.
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

// NewAnchorClient creates a gRPC client connected to the local anchor server (127.0.0.1:1993).
//
// Inputs: none.
//
// Outputs:
//   - pb.AnchorClient. The gRPC client connected to 127.0.0.1:1993.
//   - err: error. Non-nil if the connection fails.
func NewAnchorClient() (pb.AnchorClient, error) {
	// Create a gRPC client connection
	conn, err := grpc.NewClient("127.0.0.1:1993", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	client := pb.NewAnchorClient(conn)
	return client, nil
}
