package anchor

// Anchor is the interface that we're exposing as a plugin.
// This defines the contract that both the plugin implementation
// and the host application will use to communicate.
type Anchor interface {
	// CreateAnchor creates a new anchor instance.
	// Returns an error if an anchor already exists and is running.
	CreateAnchor() error

	// DestroyAnchor destroys the anchor instance.
	// Returns an error if the anchor is still running.
	DestroyAnchor() error

	// StartAnchor starts the anchor with the provided configuration.
	// Parameters:
	//   - guardianURL: Base URL of the Guardian API
	//   - veilURL: Base URL of the Veil API
	//   - veilPort: Port number for the Veil connection
	//   - anchorToken: Bearer token for authentication
	//   - portal: Whether to run in portal mode
	StartAnchor(guardianURL, veilURL string, veilPort int, anchorToken string, portal bool) error

	// StopAnchor stops the anchor and cleans up resources.
	StopAnchor() error

	// CreateTUN creates a new TUN interface.
	// Parameters:
	//   - ifname: The name of the TUN interface
	//   - mtu: The MTU of the TUN interface
	CreateTUN(ifname string, mtu int) error

	// DestroyTUN destroys the TUN interface.
	DestroyTUN() error

	// LinkWithTUN links the anchor with a TUN interface.
	// Parameters:
	//   - tun: The TUN interface to link with
	LinkWithTUN() error

	// LinkWithFileDescriptor links the anchor with a file descriptor.
	// Parameters:
	//   - fileDescriptor: The file descriptor to link with
	LinkWithFileDescriptor(fileDescriptor int) error

	// GetID returns the ID of the anchor.
	GetID() (string, error)
}