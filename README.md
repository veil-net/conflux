# VeilNet Conflux

A lightweight software that connects to the VeilNet network through secure TUN interfaces. The VeilNet Conflux establishes encrypted connections to VeilNet, enabling secure, private networking for your applications and devices.

By running the VeilNet Conflux, you can access the decentralized VeilNet network, bypass network restrictions, and maintain privacy while browsing the internet (Rift Mode, requires at least one peer portal if in private plane).

> **⚠️ Note**: macOS (Darwin) support is experimental. Portal mode is not supported on Windows.

## Features

- **Secure TUN Interface**: Creates a virtual network interface for encrypted traffic
- **Privacy-First**: All traffic is encrypted and routed through the VeilNet network
- **Cross-Platform**: Support for Linux, macOS, Windows, and ARM architectures
- **Easy Configuration**: Simple command-line interface with environment variable support
- **Graceful Shutdown**: Proper cleanup of network interfaces and routes
- **Docker Support**: Containerized deployment with Docker and Docker Compose
- **Portal Mode**: Support for both client and portal modes
- **Control Plane**: NATS-based control plane

## Prerequisites

Before setting up your VeilNet Conflux, ensure you have:

- **Operating System**: Linux, macOS, or Windows
- **Root/Admin Access**: Required for TUN device creation and network configuration
- **Network Connectivity**: Stable internet connection
- **Guardian Account**: Access to the VeilNet Guardian service
- **Registration Token**: A registration token from [https://auth.veilnet.app](https://auth.veilnet.app) (required for primary method using `register` command)
- **Conflux Token** (for integration only): A conflux token from the Guardian service API. These tokens expire in 30 seconds and should only be used for programmatic integration. See [https://guardian.veilnet.app/docs#/](https://guardian.veilnet.app/docs#/) for API documentation.

> **Note**: macOS (Darwin) support is experimental and may require additional setup or troubleshooting.

## Quick Start

### 1. Choose Your Flow

- **Primary Method**: Use the `register` command with a Registration Token to create and start a Conflux. Registration tokens can be obtained from [https://auth.veilnet.app](https://auth.veilnet.app). This is the recommended way to connect a machine.
- **Integration Method**: The `up` command with a Conflux Token is for integration only. Conflux tokens expire in 30 seconds and should only be used for programmatic integration. For integration API documentation, see [https://guardian.veilnet.app/docs#/](https://guardian.veilnet.app/docs#/).

### 2. Choose Your Deployment Method

#### Option A: Docker (Recommended)

**Using Docker Compose:**

1. **Create docker-compose.yml**:
```yaml
services:
  veilnet-conflux:
    container_name: veilnet-conflux
    image: veilnet/conflux:nats-0.0.6
    pull_policy: always
    restart: unless-stopped
    # use this for Rift mode so that the host will use VeilNet as internet access, only available on Linux.
    # network_mode: host 
    privileged: true
    env_file:
      - .env
```

2. **Create .env file**:
```bash
VEILNET_TOKEN=your-conflux-token-here
VEILNET_PORTAL=false # or true
```

3. **Run**:
```bash
docker compose up -d
```

**Using Docker directly:**
```bash
docker run -d \
  --name veilnet-conflux \
  --privileged \
  -e VEILNET_TOKEN=your-conflux-token \
  -e VEILNET_PORTAL=false \
  veilnet/conflux:nats-0.0.6
```

#### Option B: Native Installation

1. **Download the binary**:
Download the binary from the releases page.

2. **Install as a system service (Recommended)**:
```bash
# Install the conflux as a system service
sudo ./veilnet-conflux install

# Start the service
sudo ./veilnet-conflux start

# Check service status
sudo ./veilnet-conflux status
```

> **⚠️ Note**: The `install` command is not supported on macOS at the moment. On macOS, use the direct run method below.

3. **Run the conflux directly (Primary method)**:
```bash
# Register with a registration token (no CIDR)
sudo ./veilnet-conflux register \
  -t your-registration-token

# Register with CIDR, e.g. 10.128.255.254
sudo ./veilnet-conflux register \
  -t your-registration-token \
  --cidr 10.128.255.254/16

# With portal mode enabled
sudo ./veilnet-conflux register \
  -t your-registration-token \
  -p

# Or using environment variables
export VEILNET_REGISTRATION_TOKEN="your-registration-token"
export VEILNET_PORTAL="false"

sudo ./veilnet-conflux register
```

> **Note**: Registration tokens can be obtained from [https://auth.veilnet.app](https://auth.veilnet.app). This is the primary method to connect a machine. Without a CIDR given, conflux will obtain a random VeilNet IP within the plane subnet. With a CIDR given, the conflux will have that IP address if it is available.

**For integration only**: You can use the `up` command with a conflux token (expires in 30 seconds). See [https://guardian.veilnet.app/docs#/](https://guardian.veilnet.app/docs#/) for API documentation.

### 3. Verify Your Connection

1. **Check network interface**: The conflux creates a `veilnet` TUN interface
2. **Monitor logs**: Check the application logs for connection status
3. **Test connectivity**: Verify your traffic is being routed through VeilNet

## Configuration

### Command Line Options

The VeilNet Conflux supports multiple commands:

#### `up` Command - Start the Conflux (Integration Only)

> **⚠️ Important**: This command is for integration only. Conflux tokens expire in 30 seconds and should only be used for programmatic integration. For regular usage, use the `register` command instead. For integration API documentation, see [https://guardian.veilnet.app/docs#/](https://guardian.veilnet.app/docs#/).

| Option | Flag | Description | Required | Default |
|--------|------|-------------|----------|---------|
| Token | `-t, --token` | Your conflux authentication token (expires in 30 seconds) | Yes | - |
| Portal | `-p, --portal` | Enable portal mode | No | `false` |
| Guardian | `-g, --guardian` | The Guardian URL (Authentication Server) | No | `https://guardian.veilnet.app` |

#### `register` Command - Register and Start a Conflux

> **Note**: This is the primary method to connect a machine. Registration tokens can be obtained from [https://auth.veilnet.app](https://auth.veilnet.app).

| Option | Flag | Description | Required | Default |
|--------|------|-------------|----------|---------|
| Token | `-t, --token` | Registration token (Bearer) | Yes | - |
| Portal | `-p, --portal` | Enable portal mode | No | `false` |
| Guardian | `-g, --guardian` | The Guardian URL (Authentication Server) | No | `https://guardian.veilnet.app` |
| CIDR | `--cidr` | The CIDR to be used by the conflux | No | - |
| Tag | `--tag` | Optional tag for the conflux | No | - |
| Subnets | `--subnets` | The subnets to be forwarded by the conflux, separated by comma (e.g. 10.128.0.0/16,10.129.0.0/16) | No | - |

#### `down` Command - Stop the Conflux

Stops the currently running conflux service.

#### Service Management Commands

| Command | Description |
|---------|-------------|
| `install` | Install the conflux as a system service (not supported on macOS) |
| `start` | Start the installed conflux service |
| `stop` | Stop the conflux service |
| `remove` | Remove the conflux service from the system |
| `status` | Check the status of the conflux service |

#### `docker` Command - Run the Conflux Service in Docker

| Option | Flag | Description | Required | Default |
|--------|------|-------------|----------|---------|
| Token | `-t, --token` | Registration token (Bearer) | Yes | - |
| Portal | `-p, --portal` | Enable portal mode | No | `false` |
| Guardian | `-g, --guardian` | The Guardian URL (Authentication Server) | No | `https://guardian.veilnet.app` |
| Tag | `--tag` | The tag for the conflux | No | - |
| CIDR | `--cidr` | The CIDR of the conflux | No | - |
| Subnets | `--subnets` | The subnets to be forwarded by the conflux, separated by comma (e.g. 10.128.0.0/16,10.129.0.0/16) | No | - |

#### `unregister` Command - Unregister the Conflux

Unregisters the conflux and stops the service. This command takes no parameters.

> **Note**: This is the primary method to unregister and disconnect a machine.

 

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `VEILNET_CONFLUX_TOKEN` | Conflux authentication token (for `up`) | Yes (for `up`) | - |
| `VEILNET_REGISTRATION_TOKEN` | Registration token (for `register`) | Yes (for `register`) | - |
| `VEILNET_PORTAL` | Enable portal mode (`true` or `false`) | No | `false` |
| `VEILNET_GUARDIAN` | The Guardian URL (Authentication Server) | No | `https://guardian.veilnet.app` |
| `VEILNET_CONFLUX_TAG` | Optional tag for the conflux | No | - |
| `VEILNET_CONFLUX_CIDR` | The CIDR to be used by the conflux (for `register`) | No | - |
| `VEILNET_CONFLUX_SUBNETS` | The subnets to be forwarded by the conflux, separated by comma (for `register` and `docker`) | No | - |

### Configuration Priority

Configuration values are loaded in this order (later overrides earlier):

1. **Default values** (hardcoded defaults)
2. **Environment variables** (with `VEILNET_` prefix)
3. **Command line flags** (highest priority)

## Usage Examples

### Basic Connection and Disconnection (Primary Method)
```bash
# Register and start the conflux (primary method)
# Registration tokens can be obtained from https://auth.veilnet.app
sudo ./veilnet-conflux register \
  -t your-registration-token

# Unregister and stop the conflux
sudo ./veilnet-conflux unregister
```

### Integration Method (Conflux Token - 30s expiration)
```bash
# Start the conflux with a conflux token (for integration only)
# ⚠️ Warning: Conflux tokens expire in 30 seconds
# For integration API documentation, see https://guardian.veilnet.app/docs#/
sudo ./veilnet-conflux up \
  -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Stop the conflux
sudo ./veilnet-conflux down
```

### Portal Mode
```bash
# Primary method: Register with portal mode enabled
sudo ./veilnet-conflux register \
  -t your-registration-token \
  -p

# Integration method (conflux token expires in 30s)
sudo ./veilnet-conflux up \
  -t your-conflux-token \
  -p
```

### Register and Start a Conflux (Primary Method)
```bash
# Registration tokens can be obtained from https://auth.veilnet.app
./veilnet-conflux register \
  -t your-registration-token \
  -p

# With CIDR and subnets
./veilnet-conflux register \
  -t your-registration-token \
  --cidr 10.128.255.254/16 \
  --subnets 10.128.0.0/16,10.129.0.0/16
```

### Using Environment Variables
```bash
# Primary method: Using registration token
export VEILNET_REGISTRATION_TOKEN="your-registration-token"
export VEILNET_PORTAL="false"

sudo ./veilnet-conflux register

# Integration method: Using conflux token (expires in 30s)
export VEILNET_CONFLUX_TOKEN="your-conflux-token"
export VEILNET_PORTAL="false"

sudo ./veilnet-conflux up
```

### Service Management
```bash
# Install as a system service (recommended for Linux/Windows)
# Note: Not supported on macOS
sudo ./veilnet-conflux install

# Start the service
sudo ./veilnet-conflux start

# Check service status
sudo ./veilnet-conflux status

# Stop the service
sudo ./veilnet-conflux stop

# Remove the service
sudo ./veilnet-conflux remove
```

### Register and Unregister Commands (Primary Method)
```bash
# Register a new conflux (primary method)
# Registration tokens can be obtained from https://auth.veilnet.app
./veilnet-conflux register \
  -t your-registration-token \
  -p

# Unregister the conflux (takes no parameters)
./veilnet-conflux unregister
```

### Integration with Conflux Token (30s expiration)
```bash
# For programmatic integration only
# ⚠️ Warning: Conflux tokens expire in 30 seconds
# API documentation: https://guardian.veilnet.app/docs#/
./veilnet-conflux up \
  -t your-conflux-token \
  -p
```

### Docker with Custom Configuration
```bash
docker run -d \
  --name veilnet-conflux \
  --privileged \
  -e VEILNET_TOKEN="your-token" \
  -e VEILNET_PORTAL="false" \
  veilnet/conflux:nats-0.0.6
```

## Network Configuration

The VeilNet Conflux automatically configures your network:

1. **Creates TUN Interface**: Establishes a virtual network interface named `veilnet`
2. **Configures Routes**: Sets up routing to direct traffic through the VeilNet network
3. **Bypass Routes**: Adds routes for Cloudflare STUN/TURN servers to maintain connectivity
4. **Cleanup**: Properly removes all network changes on shutdown

### Network Interface Details

- **Interface Name**: `veilnet`
- **Type**: TUN (Layer 3)
- **MTU**: 1500
- **IP Assignment**: Dynamic from Guardian service

### Portal Mode vs Rift Mode

- **Rift Mode** (default): Routes all traffic through the VeilNet network
- **Portal Mode** (`-p` flag): Acts as a gateway, forwarding traffic from veilnet to other devices or networks

## Monitoring and Maintenance

### Logs

The conflux uses structured logging. Check logs for detailed information:

```bash
# Docker logs
docker logs veilnet-conflux -f

# System logs (if running as service)
sudo journalctl -u veilnet-conflux -f

# Direct logs
sudo ./veilnet-conflux up 2>&1 | tee veilnet.log
```

### Graceful Shutdown

The conflux handles shutdown signals (SIGINT, SIGTERM) gracefully:

1. **Stops Anchor**: Disconnects from Guardian service
2. **Cleans Routes**: Removes all VeilNet-related network routes
3. **Removes Interface**: Deletes the TUN interface
4. **Restores Default Route**: Restores original network configuration

### Updates

To update your conflux:

```bash
# Docker
docker-compose pull
docker-compose up -d

# Native
# Download new binary and restart
```

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Ensure running with sudo for native installation
sudo ./veilnet-conflux up

# For Docker, ensure --privileged flag is set
```

**TUN Device Creation Failed**
```bash
# Check if TUN module is loaded (Linux)
lsmod | grep tun

# Load TUN module if needed (Linux)
sudo modprobe tun

# For Docker, ensure --privileged flag is set
```

**Network Configuration Failed**
```bash
# Check if iproute2 is installed (Linux)
which ip

# Install if missing
sudo apt install iproute2  # Ubuntu/Debian
sudo yum install iproute   # CentOS/RHEL
```

**Connection to Guardian Failed**
```bash
# Check network connectivity
curl https://guardian.veilnet.app

# Verify token is correct
# Check logs for authentication errors
```

**Route Conflicts**
```bash
# Check existing routes
ip route show

# Remove conflicting routes manually if needed
sudo ip route del default dev veilnet
```

**Registration/Unregistration Issues**
```bash
# Verify your email and password are correct
# Check that the conflux name is unique
# Ensure you have proper permissions for the plane
```

### macOS (Darwin) Specific Issues

> **⚠️ Note**: macOS support is experimental and may have additional issues.

**TUN/TAP Interface Issues**
```bash
# macOS may require additional permissions
# Check System Preferences > Security & Privacy > Privacy > Full Disk Access
# Ensure Terminal or your terminal app has full disk access
```

**Network Configuration on macOS**
```bash
# macOS uses different network configuration tools
# The conflux may not work as expected on macOS
# Consider using Docker for better compatibility
```

### Windows Specific Issues

> **⚠️ Note**: Portal mode is not supported on Windows.

**TUN Device Issues**
```bash
# Windows requires the wintun.dll driver
# The conflux automatically extracts and uses the embedded driver
```

## License

This project is licensed under the CC-BY-NC-ND-4.0 License.
