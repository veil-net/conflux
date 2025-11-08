//go:build windows
// +build windows

package cli

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/json"

	"github.com/labstack/echo/v4"
	"github.com/veil-net/veilnet"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	tun "golang.zx2c4.com/wireguard/tun"
)

//go:embed wintun.dll
var wintunDLL []byte

type conflux struct {
	anchor           *veilnet.Anchor
	api              *API
	device           tun.Device
	portal           bool
	gateway          string
	iface            string
	bypassRoutes     sync.Map
	ipForwardEnabled bool
	metricsServer    *http.Server

	anchorMutex sync.Mutex
	anchorOnce  sync.Once
}

func newConflux() *conflux {
	c := &conflux{}
	c.api = newAPI(c)
	return c
}

func (c *conflux) Run() error {

	// Check if the conflux is running as a Windows service
	isWindowsService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}

	// If the conflux is running as a Windows service, run as a Windows service
	if isWindowsService {
		return svc.Run("veilnet", c)
	}

	// If the conflux is not running as a Windows service, run as a HTTP server
	return c.api.Run()
}

func (c *conflux) Install() error {

	// Get the executable path
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// Create the service configuration
	cfg := mgr.Config{
		DisplayName:      "VeilNet Conflux",
		StartType:        mgr.StartAutomatic,
		Description:      "VeilNet Conflux service",
		ServiceStartName: "LocalSystem",
	}

	// Create the service
	s, err := m.CreateService("VeilNet Conflux", exe, cfg)
	if err != nil {
		return err
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return fmt.Errorf("failed to start VeilNet Conflux service: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

func (c *conflux) Start() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		return fmt.Errorf("failed to open VeilNet Conflux service: %v", err)
	}
	defer s.Close()

	// Start the service
	err = s.Start()
	if err != nil {
		return fmt.Errorf("failed to start VeilNet Conflux service: %v", err)
	}

	veilnet.Logger.Sugar().Info("VeilNet Conflux service started successfully")
	return nil
}

func (c *conflux) Stop() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		return fmt.Errorf("failed to open VeilNet Conflux service: %v", err)
	}
	defer s.Close()

	// Stop the service
	_, err = s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop VeilNet Conflux service: %v", err)
	}

	veilnet.Logger.Sugar().Info("VeilNet Conflux service stopped successfully")
	return nil
}

func (c *conflux) Remove() error {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		return fmt.Errorf("failed to open VeilNet Conflux service: %v", err)
	}
	defer s.Close()

	// Stop the service first
	s.Control(svc.Stop)

	// Delete the service
	err = s.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete VeilNet Conflux service: %v", err)
	}

	veilnet.Logger.Sugar().Info("VeilNet Conflux service removed successfully")
	return nil
}

func (c *conflux) Status() (bool, error) {
	// Connect to the service manager
	m, err := mgr.Connect()
	if err != nil {
		return false, fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService("VeilNet Conflux")
	if err != nil {
		return false, fmt.Errorf("failed to open VeilNet Conflux service: %v", err)
	}
	defer s.Close()

	// Get the service status
	status, err := s.Query()
	if err != nil {
		return false, fmt.Errorf("failed to query VeilNet Conflux service: %v", err)
	}
	if status.State != svc.Running {
		return false, fmt.Errorf("VeilNet Conflux service is not running")
	}
	return true, nil
}

func (c *conflux) Metrics(name string) int {

	// Get the metrics
	metrics := c.anchor.GetAnchorMetrics(name)
	return metrics
}

func (c *conflux) StartVeilNet(apiBaseURL, anchorToken string, portal bool) error {

	// Lock the anchor mutex
	c.anchorMutex.Lock()
	defer c.anchorMutex.Unlock()

	// initialize the anchor once
	c.anchorOnce = sync.Once{}

	// Set portal
	c.portal = portal

	// Get the default gateway and interface
	err := c.DetectHostGateway()
	if err != nil {
		return err
	}

	// Set bypass routes
	c.AddBypassRoutes()

	// Close existing TUN device if any (defensive cleanup)
	if c.device != nil {
		c.CloseTUN()
		c.device = nil
	}

	// Create the TUN device
	err = c.CreateTUN()
	if err != nil {
		return err
	}

	//Close existing anchor
	if c.anchor != nil {
		c.StopVeilNet()
		c.anchor = nil
	}

	// Start the anchor
	c.anchor = veilnet.NewAnchor()
	err = c.anchor.Start(apiBaseURL, anchorToken, false)
	if err != nil {
		return err
	}

	// Get the IP address
	cidr, err := c.anchor.GetCIDR()
	if err != nil {
		return err
	}
	ipAddr, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ip := ipAddr.String()
	netmask := fmt.Sprintf("%d.%d.%d.%d", ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3])

	// Configure the host
	err = c.ConfigHost(ip, netmask)
	if err != nil {
		return err
	}

	// Start the ingress and egress threads
	go c.ingress()
	go c.egress()

	// Close existing metrics server
	if c.metricsServer != nil {
		c.metricsServer.Shutdown(context.Background())
		c.metricsServer = nil
	}

	// Start the metrics server
	c.metricsServer = &http.Server{
		Addr:    ":9090",
		Handler: c.anchor.Metrics.GetHandler(),
	}
	go func() {
		if err := c.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			veilnet.Logger.Sugar().Errorf("metrics server error: %v", err)
		}
	}()

	return nil
}

func (c *conflux) StopVeilNet() {

	c.anchorOnce.Do(func() {

		// Lock the anchor mutex
		c.anchorMutex.Lock()
		defer c.anchorMutex.Unlock()

		// Stop the metrics server
		if c.metricsServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.metricsServer.Shutdown(ctx); err != nil {
				veilnet.Logger.Sugar().Errorf("failed to stop metrics server: %v", err)
			}
			c.metricsServer = nil
		}

		// Stop the anchor
		if c.anchor != nil {
			c.anchor.Stop()
			c.anchor = nil
		}

		// Clean up the host configurations
		c.CleanHostConfiguraions()
		c.RemoveBypassRoutes()

		// Protect CloseTUN with panic recovery
		func() {
			defer func() {
				if r := recover(); r != nil {
					veilnet.Logger.Sugar().Errorf("panic in CloseTUN: %v", r)
				}
			}()
			c.CloseTUN()
			c.device = nil
		}()
	})
}

func (c *conflux) GetAnchor() *veilnet.Anchor {
	if c.anchor == nil {
		return nil
	}
	return c.anchor
}

func (c *conflux) CreateTUN() error {

	dllPath := filepath.Join(os.TempDir(), "wintun.dll")

	// Always overwrite wintun.dll in temp directory.
	if err := os.WriteFile(dllPath, wintunDLL, 0644); err != nil {
		return fmt.Errorf("write wintun.dll: %w", err)
	}

	// Set the GUID for the TUN device
	tun.WintunStaticRequestedGUID = &windows.GUID{
		Data1: 0x564E4554,                                              // "VNET" in ASCII
		Data2: 0x564E,                                                  // "VN" in ASCII
		Data3: 0x4554,                                                  // "ET" in ASCII
		Data4: [8]byte{0x56, 0x45, 0x49, 0x4C, 0x4E, 0x45, 0x54, 0x00}, // "VEILNET" in ASCII
	}

	// Add the temp directory to the DLL search path for this process.
	if err := windows.SetDllDirectory(os.TempDir()); err != nil {
		return fmt.Errorf("failed to set DLL search path: %w", err)
	}

	// Create a new TUN device
	tun, err := tun.CreateTUN("veilnet", 1500)
	if err != nil {
		return err
	}
	c.device = tun
	return nil
}

func (c *conflux) CloseTUN() {
	if c.device != nil {
		err := c.device.Close()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to close TUN device: %v", err)
		}
	}
}

func (c *conflux) DetectHostGateway() error {

	// Get the host default gateway and interface
	cmd := exec.Command("route", "print", "0.0.0.0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to get host default gateway: %s", string(out))
		return err
	}

	// Parse the output
	lines := strings.Split(string(out), "\n")
	var gateway string
	var iface string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gateway = fields[2]
			iface = fields[3]
			break
		}
	}

	// If the host default gateway or interface is not found, return an error
	if gateway == "" || iface == "" {
		veilnet.Logger.Sugar().Errorf("Host default gateway or interface not found")
		return fmt.Errorf("host default gateway or interface not found")
	}

	// Store the host default gateway and interface
	veilnet.Logger.Sugar().Infof("Found Host Default gateway: %s via interface %s", gateway, iface)
	c.gateway = gateway
	c.iface = iface
	return nil
}

func (c *conflux) AddBypassRoutes() {
	hosts := []string{"stun.cloudflare.com", "turn.cloudflare.com", "guardian.veilnet.app", "nats.veilnet.app"}

	for _, host := range hosts {
		// Resolve IP addresses
		ips, err := net.LookupIP(host)
		if err != nil {
			veilnet.Logger.Sugar().Errorf("Failed to resolve %s: %v", host, err)
			continue
		}

		for _, ip := range ips {
			// Add route for IPv4 addresses
			if ip4 := ip.To4(); ip4 != nil {
				dest := ip4.String()
				cmd := exec.Command("route", "add", dest, "mask", "255.255.255.255", c.gateway)
				out, err := cmd.CombinedOutput()
				if err != nil {
					veilnet.Logger.Sugar().Debugf("failed to add bypass route for %s: %s", host, string(out))
					continue
				} else {
					// Store the bypass route
					c.bypassRoutes.Store(host, dest)
					veilnet.Logger.Sugar().Infof("Added bypass route for %s: %s", host, dest)
				}
			}
		}
	}
}

func (c *conflux) RemoveBypassRoutes() {
	c.bypassRoutes.Range(func(key, value interface{}) bool {
		// Remove bypass route
		cmd := exec.Command("route", "delete", value.(string), "mask", "255.255.255.255", c.gateway)
		out, err := cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Debugf("failed to clear bypass route for %s: %s", key, string(out))
			return true
		} else {
			veilnet.Logger.Sugar().Infof("Removed bypass route for %s: %s", key, value.(string))
			return true
		}
	})
}

func (c *conflux) ingress() {

	defer func() {
		if r := recover(); r != nil {
			veilnet.Logger.Sugar().Errorf("panic in ingress: %v", r)
		}
	}()

	bufs := make([][]byte, c.device.BatchSize())

	for {
		select {
		case <-c.anchor.Ctx.Done():
			veilnet.Logger.Sugar().Info("Conflux ingress stopped")
			return
		default:
			n := c.anchor.Read(bufs, c.device.BatchSize())
			if n > 0 {
				for i := 0; i < n; i++ {
					wgBuf := make([]byte, 16+len(bufs[i]))
					copy(wgBuf[16:], bufs[i])
					bufs[i] = wgBuf
				}
				_, err := c.device.Write(bufs[:n], 16)
				if err != nil {
					veilnet.Logger.Sugar().Errorf("failed to write to TUN device: %v", err)
					continue
				}
			}
		}
	}
}

func (c *conflux) egress() {

	defer func() {
		if r := recover(); r != nil {
			veilnet.Logger.Sugar().Errorf("panic in egress: %v", r)
		}
	}()

	// Get the TUN MTU
	mtu, err := c.device.MTU()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to get TUN MTU: %v", err)
		// Use default MTU if we can't get the actual one
		mtu = 1500
	}

	// Create the buffers
	bufs := make([][]byte, c.device.BatchSize())
	sizes := make([]int, c.device.BatchSize())
	// Pre-allocate buffers
	for i := range bufs {
		bufs[i] = make([]byte, mtu)
	}

	for {
		select {
		case <-c.anchor.Ctx.Done():
			veilnet.Logger.Sugar().Info("Conflux egress stopped")
			return
		default:
			n, err := c.device.Read(bufs, sizes, 0)
			if err != nil {
				continue
			}
			if n > 0 {
				c.anchor.Write(bufs[:n], sizes[:n])
			}
		}
	}
}

// ConfigHost configures the TUN interface with the given IP address and netmask
// It also sets up iptables FORWARD rules and NAT for the TUN interface
// It also enables IP forwarding if it is not already enabled
func (c *conflux) ConfigHost(ip, netmask string) error {

	// Set the IPv4 address and netmask (non-persistent)
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address", "name=veilnet", "static", ip, netmask, "store=active")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to configure VeilNet TUN IP address: %s", string(out))
		return err
	}
	veilnet.Logger.Sugar().Infof("Set VeilNet TUN to %s", ip)

	// Set the DNS server (non-persistent)
	cmd = exec.Command("netsh", "interface", "ipv4", "add", "dnsserver", "name=veilnet", "address=1.1.1.1", "index=1", "store=active")
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to configure VeilNet TUN DNS: %s", string(out))
		return err
	}
	veilnet.Logger.Sugar().Infof("Set VeilNet TUN DNS to 1.1.1.1")

	// Get the interface index
	iface, err := net.InterfaceByName("veilnet")
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to get VeilNet TUN interface index: %v", err)
		return err
	}
	veilnet.Logger.Sugar().Infof("Got VeilNet TUN interface index: %d", iface.Index)

	go func() {
		for {
			select {
			case <-c.anchor.Ctx.Done():
				return
			case subnet := <-c.anchor.PlaneNetworksAddQueue:
				_, ipNet, err := net.ParseCIDR(subnet)
				if err != nil {
					veilnet.Logger.Sugar().Warnf("failed to parse plane local network subnet %s: %v", subnet, err)
					continue
				}
				ip := strings.Split(subnet, "/")[0]
				netmask := fmt.Sprintf("%d.%d.%d.%d", ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3])
				cmd := exec.Command("route", "add", ip, "mask", netmask, ip, "if", strconv.Itoa(iface.Index))
				out, err := cmd.CombinedOutput()
				if err != nil {
					veilnet.Logger.Sugar().Warnf("failed to set plane local network route: %s", string(out))
					continue
				}
				veilnet.Logger.Sugar().Infof("Set plane local network route for %s", subnet)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-c.anchor.Ctx.Done():
				return
			case subnet := <-c.anchor.PlaneNetworksRemoveQueue:

				_, ipNet, err := net.ParseCIDR(subnet)
				if err != nil {
					veilnet.Logger.Sugar().Warnf("failed to parse plane local network subnet %s: %v", subnet, err)
					continue
				}
				ip := strings.Split(subnet, "/")[0]
				netmask := fmt.Sprintf("%d.%d.%d.%d", ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3])
				cmd := exec.Command("route", "delete", ip, "mask", netmask, ip, "if", strconv.Itoa(iface.Index))
				out, err := cmd.CombinedOutput()
				if err != nil {
					veilnet.Logger.Sugar().Warnf("failed to remove plane local network route: %s", string(out))
					continue
				}
				veilnet.Logger.Sugar().Infof("Removed plane local network route for %s", subnet)
			}
		}
	}()

	if !c.portal {
		// Set the default route
		cmd = exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", ip, "metric", "5", "if", strconv.Itoa(iface.Index))
		out, err := cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to set VeilNet TUN as alternate gateway: %s", string(out))
			return err
		}
		veilnet.Logger.Sugar().Infof("Set VeilNet TUN as preferred gateway")
	}

	return nil
}

// CleanHostConfiguraions removes the iptables FORWARD rules and NAT rule for the TUN interface
// It also disables IP forwarding if it was not enabled
func (c *conflux) CleanHostConfiguraions() {

	if !c.portal {
		// Get the interface index
		iface, err := net.InterfaceByName("veilnet")
		if err != nil {
			veilnet.Logger.Sugar().Debugf("failed to get VeilNet TUN interface index: %v", err)
			return
		}

		// Remove the route
		cmd := exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0", "if", strconv.Itoa(iface.Index))
		out, err := cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Debugf("failed to remove VeilNet TUN route: %s", string(out))
		} else {
			veilnet.Logger.Sugar().Infof("Removed VeilNet TUN as preferred gateway")
		}
	}

}

func (c *conflux) Execute(args []string, changeRequests <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	// Create the server
	c.api.server = echo.New()

	// Register routes
	c.api.server.POST("/up", c.api.up)
	c.api.server.POST("/down", c.api.down)
	c.api.server.POST("/register", c.api.register)
	c.api.server.POST("/unregister", c.api.unregister)
	c.api.server.GET("/metrics/:name", c.api.metrics)
	// Start server
	go func() {
		if err := c.api.server.Start(":1993"); err != nil && err != http.ErrServerClosed {
			c.StopVeilNet()
			veilnet.Logger.Sugar().Fatalf("Conflux service encountered an error: %v", err)
		}
	}()
	// Load existing registration data
	var register Register
	tmpDir, err := os.UserConfigDir()
	if err == nil {
		confluxDir := filepath.Join(tmpDir, "conflux")
		confluxFile := filepath.Join(confluxDir, "conflux.json")
		registrationDataFile, err := os.ReadFile(confluxFile)
		if err == nil {
			json.Unmarshal(registrationDataFile, &register)
		}
	} else {
		guardian := os.Getenv("VEILNET_GUARDIAN")
		token := os.Getenv("VEILNET_REGISTRATION_TOKEN")
		tag := os.Getenv("VEILNET_CONFLUX_TAG")
		cidr := os.Getenv("VEILNET_CONFLUX_CIDR")
		portal := os.Getenv("VEILNET_PORTAL") == "true"
		subnets := os.Getenv("VEILNET_CONFLUX_SUBNETS")
		register = Register{
			Tag:      tag,
			Cidr:     cidr,
			Guardian: guardian,
			Token:    token,
			Portal:   portal,
			Subnets:  subnets,
		}
	}
	if register.Guardian != "" || register.Token != "" {
		go func() {
			veilnet.Logger.Sugar().Infof("registering conflux from loaded registration data or environment variables")
			time.Sleep(1 * time.Second)
			err := register.Run()
			if err != nil {
				veilnet.Logger.Sugar().Errorf("failed to register conflux: %v", err)
			}
		}()
	}
	// Set the status to running
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for changeRequest := range changeRequests {
		switch changeRequest.Cmd {
		case svc.Interrogate:
			changes <- changeRequest.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.api.server.Shutdown(ctx); err != nil {
				veilnet.Logger.Sugar().Errorf("shutting down the server: %v", err)
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
			// Stop the veilnet
			c.StopVeilNet()
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}

	return false, 0
}
