# VeilNet Conflux

VeilNet Conflux is a networking service that connects to VeilNet, a decentralized post-quantum secure network. This guide covers installation and deployment options.

## Announcement

### Upcoming Update

Later this month, we will release a major update that is not compatible with the current version. This new update will bring:
- **Identity DNS**: A unique decentralized DNS system that performs DNS queries via Anchor control. You will be able to access Conflux instances using **non-unique** DNS names with built-in automatic load balancing. More details will be shared upon release.
- **Architecture Overhaul**: Currently, VeilNet Conflux runs as a background service. Once started, the only way to stop it is to disable or remove the service. In the next release, it will run a mini local-only API server that allows you to start or stop it without needing to remove or reinstall the system service.
- **EXP3**: Currently, the Anchor protocol utilizes a gossip protocol inspired by the Ant Colony algorithm to terminate sub-optimal paths and a Q-learning algorithm for path discovery. We will replace both with a single MAB EXP3 algorithm.

### Android Library

You can now build your own VPN app using our pre-compiled AAR library for Android. It will be available in the releases section.

You will still need a VeilNet account, but you can inject the registration token into your app as an API key, so your app users do not need to have a VeilNet account.

Code examples have been added, and you are welcome to ask for help at: https://discord.gg/yKCZCZutDR

### Guardian Server API

The Guardian server API schema is now available in this repository. You can also access it at https://guardian.veilnet.app/docs#/

## How It Works

VeilNet is an ephemeral secure network that differs fundamentally from traditional Peer-to-Peer mesh overlay VPN networks. For detailed information, see the [official documentation](https://veilnet.net/docs).

### Key Components

- **VeilNet Master**: The control-channel message broker that enables the Reinforcement Learning routing algorithm used in the Anchor protocol.
- **VeilNet Guardian**: The authentication server for both users and VeilNet Conflux nodes. User authentication relies on Supabase, while Conflux node authentication uses a JWT system with both long-lived and short-lived tokens.
- **VeilNet Conflux**: The connector software (this project) that runs on virtual or physical machines, as well as container environments, to form the decentralized network.

### Key Differences from Traditional VPNs

- **No Coordination Server**: VeilNet is a decentralized network with no central server managing network state. The network forms automatically through VeilNet Conflux nodes. Encryption keys and routing decisions are generated at runtime and never stored. Conflux nodes do not synchronize configuration files.
- **Non-mesh and Ephemeral**: Data channels between nodes are created on demand and dissolve when idle. No connection is persistent. Multi-hop transmission is natively supported by the Anchor protocol, resulting in a topology that is never fixed or static.
- **Post-Quantum Cryptography**: VeilNet uses Kyber Key Exchange Mechanism and Dilithium Digital Signature, providing post-quantum security. It uses symmetric encryption (AES-GCM-256) rather than asymmetric encryption, with no public or private keys.

### How VeilNet Conflux Works

When a VeilNet Conflux instance starts:

1. **Authentication**: The instance authenticates with VeilNet Guardian using a registration token or conflux token, receiving a certificate that permits joining the global control channel.
2. **Network Formation**: The instance joins the decentralized network through the control channel (a NATS super cluster), exchanging information with other authenticated nodes at runtime.
3. **Encryption & Routing**: 
   - Each Conflux derives shared secrets locally using Kyber KEM
   - Packets are authenticated using Dilithium digital signatures
   - Routing uses a multi-agent cooperative reinforcement learning algorithm
   - Routes are established dynamically: **streams** (logical secure channels), **routes** (multi-hop forwarding), and **tethers** (aggregated WebRTC data channels)
4. **Access Control**: Identity-based access control is enforced at the Conflux instance level. Only verified instances may communicate; untrusted instances are silently ignored.
5. **Self-Healing**: Conflux instances automatically handle load balancing and route switching, self-healing from network failures and guaranteeing data delivery unless the destination is offline.

VeilNet Conflux instances can automatically serve as relays for other verified instances without any configuration, significantly reducing the need for external relays.

## How VeilNet Compares

Not all secure networks are created equal. The following table compares VeilNet with traditional VPN solutions:

| Feature | WireGuard | Tailscale | VeilNet |
|---------|-----------|-----------|---------|
| **Architecture** | Centralised Hub | P2P Mesh | **Decentralised Non-Mesh Overlay** |
| **Encryption** | ChaCha20 & Poly1035 | ChaCha20 & Poly1035 | **Kyber KEM & Dilithium DSA & AES-GCM 256** |
| **Routing** | Static Route Table | Static Route Table | **Reinforcement Learning** |
| **Resilience** | Single-point failures | No alternative route if P2P fails | **Dynamic Self-recovering Route** |
| **Scalability Complexity** | Not possible for scaling | Exponential increase | **Linear increase** |
| **Tunneling** | Static Tunnel | Static Tunnel + NAT Traversal | **Ephemeral Link + WebRTC** |
| **Set-up** | Manual Config | Central Coordination Server | **Self-config with decentralised control plane** |
| **Software Defined Network** | N/A | Limited | **AI-Powered** |
| **Geo-location Control** | N/A | N/A | **Yes** |
| **Deployment Complexity** | High | Medium | **Easy** |
| **Access Control** | N/A | Complex Json-based & Subnet Level | **Easy Identity Affinity & Packet Level** |
| **Current Multi-link Transmission** | N/A | N/A | **Yes** |
| **Peer Relay / Multi-Hop** | N/A | Manual Config & Experimental | **Self-Learning & Natively Supported** |

For more details, visit the [VeilNet homepage](https://veilnet.net/).

## How Connectivity is Established

VeilNet establishes connectivity through a decentralized, ephemeral architecture that differs fundamentally from traditional overlay VPNs. For a comparison with other overlay VPN solutions, see the [official comparison documentation](https://veilnet.net/docs/veilnet-vs-overlay-vpns/).

### Control Channel (VeilNet Master)

All Conflux instances connect to **VeilNet Master**, the control channel (not a server entity) implemented as a NATS super cluster. The Master is a message broker channel that simply relays control messages between Conflux instances. It does not control the network, manage network state, or make routing decisions. This allows nodes to exchange routing information, discover paths, and coordinate without a central coordination server managing network state.

```mermaid
graph TB
    subgraph "Control Channel"
        Master[VeilNet Master<br/>Message Broker Channel]
    end
    
    subgraph "Conflux Instances"
        C1[Conflux A]
        C2[Conflux B]
        C3[Conflux C]
        C4[Conflux D]
    end
    
    C1 -.->|Control Messages| Master
    C2 -.->|Control Messages| Master
    C3 -.->|Control Messages| Master
    C4 -.->|Control Messages| Master
    
    C1 <-->|Direct Data<br/>Communication| C2
    C1 <-->|Direct Data<br/>Communication| C3
    C2 <-->|Direct Data<br/>Communication| C4
    C3 <-->|Direct Data<br/>Communication| C4
    
    style Master fill:#4a90e2,color:#fff
    style C1 fill:#f5a623,color:#fff
    style C2 fill:#f5a623,color:#fff
    style C3 fill:#f5a623,color:#fff
    style C4 fill:#f5a623,color:#fff
```

**Note**: VeilNet Master is a **channel**, not a server entity. It only relays control messages and does not manage network state or routing decisions.

### Data Transmission Flow

#### Outbound (Egress) Path

When a Conflux instance needs to send data:

1. **TUN Interface**: The Conflux reads packets from the TUN interface (MTU 1500, with jumbo frame support planned for the future).

2. **Egresser Creation**: For each destination, the Conflux creates an **egresser** (outbound handler) that manages the transmission to that specific destination.

3. **Stream Establishment**: The egresser establishes a secure **stream** via the Anchor protocol. A stream is a logical secure channel per destination.

4. **Route Discovery**: The egresser finds a multi-hop or direct path as a **route** using the reinforcement learning routing algorithm. Routes can be:
   - Direct (single hop)
   - Multi-hop (through intermediate Conflux instances)

5. **Tether Creation**: The egresser establishes a group of WebRTC data channels as a **tether** to the next hop. A tether aggregates multiple WebRTC data channels for improved performance and reliability.

6. **Data Transmission**: The encrypted data is transmitted to the next hop through the tether.

```mermaid
flowchart LR
    subgraph "Source Conflux"
        TUN[TUN Interface<br/>MTU 1500]
        EGR[Egresser<br/>per destination]
        STR[Stream<br/>Secure Channel]
        RTE[Route<br/>Multi-hop Path]
        TTH[Tether<br/>WebRTC Channels]
    end
    
    subgraph "Next Hop"
        TTH2[Tether]
    end
    
    TUN -->|Read Packet| EGR
    EGR -->|Establish| STR
    STR -->|Find Path| RTE
    RTE -->|Create| TTH
    TTH -->|Encrypted Data| TTH2
    
    style TUN fill:#4a90e2,color:#fff
    style EGR fill:#f5a623,color:#fff
    style STR fill:#7ed321,color:#000
    style RTE fill:#9013fe,color:#fff
    style TTH fill:#f8e71c,color:#000
    style TTH2 fill:#f8e71c,color:#000
```

#### Inbound (Ingress) Path

When a Conflux instance receives data:

1. **Tether Reception**: The Conflux receives data from a tether (WebRTC data channels).

2. **Ingresser Creation**: For each stream, the Conflux creates an **ingresser** (inbound handler) that manages the reception from that specific source.

3. **Decryption**: The ingresser decrypts the message using the shared secret derived via Kyber KEM.

4. **TUN Write**: The decrypted packet is written to the TUN interface, making it available to the local network stack.

```mermaid
flowchart LR
    subgraph "Previous Hop"
        TTH1[Tether]
    end
    
    subgraph "Destination Conflux"
        TTH2[Tether<br/>WebRTC Channels]
        ING[Ingresser<br/>per stream]
        DCR[Decrypt<br/>Kyber KEM]
        TUN[TUN Interface<br/>MTU 1500]
    end
    
    TTH1 -->|Encrypted Data| TTH2
    TTH2 -->|Receive| ING
    ING -->|Decrypt| DCR
    DCR -->|Write Packet| TUN
    
    style TTH1 fill:#f8e71c,color:#000
    style TTH2 fill:#f8e71c,color:#000
    style ING fill:#f5a623,color:#fff
    style DCR fill:#7ed321,color:#000
    style TUN fill:#4a90e2,color:#fff
```

### Key Characteristics

- **Uni-directional Streams**: Streams are uni-directional. Transmitting and receiving are independent streams, allowing for asymmetric routing and independent path optimization.

```mermaid
graph LR
    subgraph "Conflux A"
        EGR1[Egresser 1]
        ING1[Ingresser 1]
    end
    
    subgraph "Conflux B"
        EGR2[Egresser 2]
        ING2[Ingresser 2]
    end
    
    EGR1 -->|Stream A→B| ING2
    EGR2 -->|Stream B→A| ING1
    
    style EGR1 fill:#f5a623,color:#fff
    style ING1 fill:#f5a623,color:#fff
    style EGR2 fill:#4a90e2,color:#fff
    style ING2 fill:#4a90e2,color:#fff
```

- **Resource Sharing**: Streams, routes, and tethers may be shared by multiple egressers or ingressers, improving efficiency and reducing overhead.

```mermaid
graph TB
    subgraph "Shared Resources"
        STR[Stream]
        RTE[Route]
        TTH[Tether]
    end
    
    EGR1[Egresser 1] --> STR
    EGR2[Egresser 2] --> STR
    EGR3[Egresser 3] --> STR
    
    STR --> RTE
    RTE --> TTH
    
    style STR fill:#7ed321,color:#000
    style RTE fill:#9013fe,color:#fff
    style TTH fill:#f8e71c,color:#000
    style EGR1 fill:#f5a623,color:#fff
    style EGR2 fill:#f5a623,color:#fff
    style EGR3 fill:#f5a623,color:#fff
```

- **WebRTC Data Channels**: Since WebRTC handles data encapsulation and segmentation, the TUN interface created by VeilNet has an MTU of 1500 (with jumbo frame support planned for the future).

- **VXLAN-like Overlay**: This architecture makes VeilNet function like VXLAN but across the internet. Conflux provides access to all host networks, including:
  - VXLAN networks
  - CNI (Container Network Interface) networks
  - Container networks
  - Local networks

### Multi-Hop Routing Example

The following diagram illustrates how data flows through multiple hops in a VeilNet network:

```mermaid
sequenceDiagram
    participant App as Application
    participant TUN1 as TUN Interface<br/>(Source)
    participant CF1 as Conflux A
    participant CF2 as Conflux B<br/>(Relay)
    participant CF3 as Conflux C<br/>(Destination)
    participant TUN2 as TUN Interface<br/>(Destination)
    
    App->>TUN1: Send Packet
    TUN1->>CF1: Read Packet
    CF1->>CF1: Create Egresser
    CF1->>CF1: Establish Stream
    CF1->>CF1: Find Route (via CF2)
    CF1->>CF1: Create Tether
    CF1->>CF2: Encrypted Data
    CF2->>CF2: Create Relay
    CF2->>CF2: Find Route (to CF3)
    CF2->>CF2: Create Tether
    CF2->>CF3: Forward Encrypted Data
    CF3->>CF3: Create Ingresser
    CF3->>CF3: Decrypt
    CF3->>TUN2: Write Packet
    TUN2->>App: Deliver Packet
```

### Advantages Over Traditional Overlay VPNs

Unlike mesh-based overlay VPNs (such as Tailscale, Netbird, ZeroTier, and Nebula), VeilNet:

- **Eliminates Mesh Complexity**: No persistent peerings or exponential connection complexity. Routes are ephemeral and dissolve when idle.

- **Independent of Host Routing**: VeilNet's routing is independent of host routing tables, enabling seamless operation across containers, VMs, bare metal, and multi-cloud infrastructure without subrouters or manual route advertisements.

- **No Configuration Synchronization**: Nodes derive routing and encryption state dynamically at runtime through the decentralized control channel, eliminating the need for persistent configuration files or static peer lists.

- **Post-Quantum Security**: Uses Kyber KEM, Dilithium signatures, and AES-GCM-256 for packet-level authentication suitable for multi-hop forwarding.

This architecture enables VeilNet to operate seamlessly across physical machines, VMs, containers, Kubernetes clusters, and serverless workloads, adapting automatically to dynamic IPs, scaling clusters, and short-lived infrastructure.

## Access Control

VeilNet uses identity-based access control through **Teams**, which is fundamentally different from traditional network policies based on subnets or IP addresses. For detailed information, see the [official access control documentation](https://veilnet.net/docs/access-control/).

### What is a Team?

A **Team** in VeilNet is an identity that can be associated with Realms, Users, and VeilNet Conflux instances. It's similar to "Taint" for a node in a Kubernetes cluster, which defines affinities.

Each Team has its own cryptographic hash signature that is used by VeilNet Conflux, along with Dilithium Digital Signature for authentication in a decentralized manner. This means VeilNet Conflux maintains access control even if the VeilNet Guardian server is offline.

### How Access Control Works

VeilNet's identity-based access control is possible because VeilNet Conflux is capable of **packet-level user authentication**, which is impossible for other overlay networks based on IP networks and WireGuard.

1. **Team Association**: After a VeilNet Conflux instance authenticates with the VeilNet Guardian server and joins VeilNet, it pulls down its associated Teams (identities) granted by the owner.

2. **Packet Authentication**: 
   - When a packet is sent, a cryptographic hash is created from each identity based on the VeilNet Conflux instance's Dilithium public key
   - When a packet is received, the VeilNet Conflux calculates the cryptographic hash of its own identities based on the sender's Dilithium public key
   - Access is granted only if at least one hash matches (affinity exists)

3. **Security**: The identities are never shared on the network, are globally verifiable, and are unique to each VeilNet Conflux instance. Impersonation is impossible because:
   - **Impersonating Dilithium Public Key is impossible**: The pair of Dilithium public key and instance signature is immutable and announced when an instance joins the network
   - **Impersonating Identity Hashes is impossible**: Without the private key (stored only in memory), a malicious instance cannot produce valid packet Dilithium DSA signatures

### Associating Teams with Conflux

There are two ways to associate Team identities with a Conflux instance:

1. **Via CLI during registration**: Use the `--teams` flag (or `VEILNET_CONFLUX_TEAMS` environment variable) followed by a comma-separated list of teams:
   ```bash
   ./veilnet-conflux register -t "your-registration-token" --teams "team1,team2"
   ```
   The Conflux instance will acquire those identities if the user is a member or owner of the team. Otherwise, the team will be ignored.

2. **Via UI**: Head to the Conflux management page on the [Auth Portal](https://console.veilnet.app). Expand the Conflux card under any Realm. If the Conflux instance is operating in Portal Mode, click on team chips to add or remove team identities. Changes take effect immediately without requiring a reboot.

### How Access Control by Team Works

VeilNet access control is based on **affinity**. For two Conflux instances to communicate, they must share at least one common Team identity.

**Example**: 
- By default, following the Zero-Trust principle, Conflux instances only have the user identity
- If James wants to access Ben's local network, Ben's Conflux instance will silently drop all messages because they don't share any common identities
- To allow access, Ben must create a Team, invite James as a member, and associate the Team with both Conflux instances
- Now James and Ben can access each other's networks

A VeilNet Conflux instance can be associated with multiple teams to enable complex access control scenarios:
- A staging server associated with both "Dev" and "Stage" teams
- A development server associated with only the "Dev" team
- A production server associated with only the "Prod" team

The key principle: implement access control **based on your business logic, rather than IP address or subnet**.

## Installation

Download the latest release from [GitHub Releases](https://github.com/veil-net/conflux/releases) for your platform.

### Linux

1. Download the binary for your architecture
2. Make it executable:
   ```bash
   chmod +x veilnet-conflux
   ```
3. Move it to a system path (optional):
   ```bash
   sudo mv veilnet-conflux /usr/local/bin/
   ```

### Windows

1. Download the Windows binary from releases
2. Extract and place the executable in your desired location

### macOS

macOS is now supported. 

1. Download the macOS binary from releases
2. Make it executable:
   ```bash
   chmod +x veilnet-conflux
   ```

## System Service Installation (Primary Method)

The primary method for installing and managing VeilNet Conflux is using the `register` and `unregister` commands. These commands handle registration with VeilNet and automatic service installation.

### Registering a Conflux

The `register` command registers your conflux with VeilNet, saves the configuration, and automatically installs and starts the system service.

#### Required Parameters

- **Registration Token**: Obtained from [https://console.veilnet.app](https://console.veilnet.app)
  - Environment variable: `VEILNET_REGISTRATION_TOKEN`
  - Command flag: `-t` or `--token`

#### Optional Parameters

- **Guardian URL**: The Guardian authentication server URL (default: `https://guardian.veilnet.app`)
  - Environment variable: `VEILNET_GUARDIAN`
  - Command flag: `-g` or `--guardian`

- **Tag**: A tag for identifying the conflux
  - Environment variable: `VEILNET_CONFLUX_TAG`

- **CIDR**: The CIDR block for the conflux network
  - Environment variable: `VEILNET_CONFLUX_CIDR`

- **Portal Mode**: Enable portal mode (default: `false`)
  - Environment variable: `VEILNET_PORTAL` (set to `true` to enable)
  - Command flag: `-p` or `--portal`

- **Teams**: Comma-separated list of teams to forward (e.g., `team1,team2`)
  - Environment variable: `VEILNET_CONFLUX_TEAMS`

#### Examples

**Using environment variables (Linux/macOS):**
```bash
export VEILNET_REGISTRATION_TOKEN="your-registration-token"
export VEILNET_CONFLUX_TAG="my-conflux"
export VEILNET_GUARDIAN="https://guardian.veilnet.app"
./veilnet-conflux register
```

**Using command flags:**
```bash
./veilnet-conflux register -t "your-registration-token" --tag "my-conflux" -g "https://guardian.veilnet.app"
```

**Windows (PowerShell):**
```powershell
$env:VEILNET_REGISTRATION_TOKEN="your-registration-token"
$env:VEILNET_CONFLUX_TAG="my-conflux"
.\veilnet-conflux.exe register
```

The `register` command will:
1. Remove any existing service
2. Register the conflux with VeilNet
3. Save the registration data to the configuration directory
4. Install and start the system service

### Unregistering a Conflux

To remove the service and unregister from VeilNet:

```bash
./veilnet-conflux unregister
```

This command will:
1. Unregister the conflux from VeilNet
2. Stop and remove the system service
3. Remove the registration configuration file

### Service Management

Once registered, you can manage the service using standard system commands:

**Linux (systemd):**
```bash
# Check status
sudo systemctl status veilnet

# Start service
sudo systemctl start veilnet

# Stop service
sudo systemctl stop veilnet

# Restart service
sudo systemctl restart veilnet

# View logs
sudo journalctl -u veilnet -f
```

**Windows:**
```powershell
# Check status
Get-Service "VeilNet Conflux"

# Start service
Start-Service "VeilNet Conflux"

# Stop service
Stop-Service "VeilNet Conflux"
```

**macOS:**
```bash
# Check status
sudo launchctl list | grep org.veilnet.conflux

# Start service
sudo launchctl start org.veilnet.conflux

# Stop service
sudo launchctl stop org.veilnet.conflux
```

You can also use the conflux CLI commands:
```bash
./veilnet-conflux start    # Start the service
./veilnet-conflux stop     # Stop the service
./veilnet-conflux status   # Check service status
./veilnet-conflux remove   # Remove the service (without unregistering)
```

## Alternative Method for Integration (Secondary)

The `up` and `down` commands are designed for integration into other applications or programs. They use a conflux token directly (rather than a registration token) and are suitable for programmatic use.

### Using the `up` Command

The `up` command starts the service with a conflux token directly, without registering with VeilNet.

#### Required Parameters

- **Conflux Token**: The conflux token (not a registration token)
  - Environment variable: `VEILNET_CONFLUX_TOKEN`
  - Command flag: `-t` or `--token`

#### Optional Parameters

- **Guardian URL**: The Guardian authentication server URL (default: `https://guardian.veilnet.app`)
  - Environment variable: `VEILNET_GUARDIAN`
  - Command flag: `-g` or `--guardian`

- **Portal Mode**: Enable portal mode (default: `false`)
  - Environment variable: `VEILNET_PORTAL` (set to `true` to enable)
  - Command flag: `-p` or `--portal`

#### Example

```bash
export VEILNET_CONFLUX_TOKEN="your-conflux-token"
./veilnet-conflux up
```

Or using command flags:
```bash
./veilnet-conflux up -t "your-conflux-token" -g "https://guardian.veilnet.app"
```

The `up` command will:
1. Remove any existing service
2. Save the configuration to `up.json` (separate from registration data)
3. Install and start the system service

### Using the `down` Command

To stop and remove the service started with `up`:

```bash
./veilnet-conflux down
```

This command will:
1. Stop and remove the system service
2. Remove the `up.json` configuration file

**Note**: The `up`/`down` method saves configuration to `up.json`, which is separate from the registration data used by `register`/`unregister`. Use this method when integrating conflux into other applications or when you already have a conflux token.

## Docker Container Deployment

VeilNet Conflux can be deployed as a Docker container using the pre-built image.

### Prerequisites

- Docker and Docker Compose installed
- A `.env` file with required environment variables

### Environment Variables

Create a `.env` file in the same directory as your `docker-compose.yml`:

```env
VEILNET_CONFLUX_TOKEN=your-conflux-token
VEILNET_GUARDIAN=https://guardian.veilnet.app
VEILNET_PORTAL=false
```

### Docker Compose

Use the provided `docker-compose.yml`:

```yaml
services:
  veilnet-conflux:
    image: veilnet/conflux:beta
    container_name: veilnet-conflux
    pull_policy: always
    restart: unless-stopped
    privileged: true
    network_mode: host
    env_file:
      - .env
```

**Important Notes:**
- The container requires `privileged: true` for network operations
- The container uses `network_mode: host` for direct network access
- The image is pulled from the registry: `veilnet/conflux:beta`

### Running the Container

1. Create your `.env` file with the required environment variables
2. Start the container:
   ```bash
   docker-compose up -d
   ```

3. View logs:
   ```bash
   docker-compose logs -f
   ```

4. Stop the container:
   ```bash
   docker-compose down
   ```

### Using Docker Run

Alternatively, you can run the container directly:

```bash
docker run -d \
  --name veilnet-conflux \
  --privileged \
  --network host \
  --restart unless-stopped \
  -e VEILNET_CONFLUX_TOKEN="your-conflux-token" \
  -e VEILNET_GUARDIAN="https://guardian.veilnet.app" \
  veilnet/conflux:beta
```

## Configuration Storage

- **Linux**: `/root/.config/conflux/`
  - Registration data: `/root/.config/conflux/conflux.json`
  - Up data: `/root/.config/conflux/up.json`

- **Windows**: `C:\ProgramData\conflux` (or `%ProgramData%\conflux`)
  - Registration data: `conflux.json`
  - Up data: `up.json`

- **macOS**: `/var/root/Library/Application Support/conflux`
  - Registration data: `conflux.json`
  - Up data: `up.json`

Environment variables take precedence over saved configuration files.

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/veil-net/conflux).

