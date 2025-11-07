//go:build linux
// +build linux

package cli

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/veil-net/veilnet"
	tun "golang.zx2c4.com/wireguard/tun"
)

const SystemdUnitTemplate = `[Unit]
Description=VeilNet Service
After=network.target

[Service]
Type=simple
ExecStart={{.ExecPath}}
ExecStop=/bin/kill -TERM $MAINPID
Restart=always
RestartSec=5
User=root
Group=root
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
`

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
	return c.api.Run()
}

func (c *conflux) Install() error {
	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	// Resolve symlinks to get real path
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		realPath = exePath
	}

	// Parse and execute template
	tmpl, err := template.New("systemd").Parse(SystemdUnitTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ ExecPath string }{ExecPath: realPath}); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	// Write unit file
	unitFile := "/etc/systemd/system/veilnet.service"
	if err := os.WriteFile(unitFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write unit file: %v", err)
	}

	// Reload systemd and enable service
	cmd := exec.Command("systemctl", "daemon-reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to reload systemd: %s", string(out))
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	cmd = exec.Command("systemctl", "enable", "veilnet.service")
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to enable service: %s", string(out))
		return fmt.Errorf("failed to enable service: %v", err)
	}

	cmd = exec.Command("systemctl", "start", "veilnet.service")
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to start service: %s", string(out))
		return fmt.Errorf("failed to start service: %v", err)
	}

	veilnet.Logger.Sugar().Infof("VeilNet Conflux service installed and started")
	return nil
}

func (c *conflux) Start() error {
	cmd := exec.Command("systemctl", "start", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to start service: %s", string(out))
		return fmt.Errorf("failed to start service: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service started")
	return nil
}

func (c *conflux) Stop() error {
	cmd := exec.Command("systemctl", "stop", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to stop service: %s", string(out))
		return fmt.Errorf("failed to stop service: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")
	return nil
}

func (c *conflux) Remove() error {
	cmd := exec.Command("systemctl", "stop", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to stop service: %s", string(out))
		return err
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service stopped")

	cmd = exec.Command("systemctl", "disable", "veilnet")
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to disable service: %s", string(out))
		return fmt.Errorf("failed to disable service: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service disabled")

	unitFile := "/etc/systemd/system/veilnet.service"
	err = os.Remove(unitFile)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to remove unit file: %v", err)
		return fmt.Errorf("failed to remove unit file: %v", err)
	}

	// Reload systemd and enable service
	cmd = exec.Command("systemctl", "daemon-reload")
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to reload systemd: %s", string(out))
		return fmt.Errorf("failed to reload systemd: %v", err)
	}
	veilnet.Logger.Sugar().Infof("VeilNet Conflux service removed")

	return nil
}

func (c *conflux) Status() (bool, error) {

	// Check if the service is running
	cmd := exec.Command("systemctl", "is-active", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("VeilNet Conflux service is not running: %v", string(out))
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

	//Close existing anchor if any (defensive cleanup)
	if c.anchor != nil {
		c.StopVeilNet()
		c.anchor = nil
	}

	// Create the anchor
	c.anchor = veilnet.NewAnchor()
	err = c.anchor.Start(apiBaseURL, anchorToken, portal)
	if err != nil {
		return err
	}

	// Get the CIDR
	cidr, err := c.anchor.GetCIDR()
	if err != nil {
		return err
	}

	// Split CIDR into IP and netmask
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid CIDR format: %s", cidr)
	}
	ip := parts[0]
	netmask := parts[1]

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

func (c *conflux) Liveness() {
	if c.anchor == nil {
		return
	}
	<-c.anchor.Ctx.Done()
}

func (c *conflux) CreateTUN() error {
	var err error
	c.device, err = tun.CreateTUN("veilnet", 1500)
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to create TUN device: %v", err)
		return err
	}
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
	cmd := exec.Command("ip", "route", "show", "default")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to get default route: %s", string(out))
		return err
	}
	lines := strings.Split(string(out), "\n")
	var gateway, iface string
	for _, line := range lines {
		if strings.HasPrefix(line, "default") {
			fields := strings.Fields(line)
			for i := 0; i < len(fields); i++ {
				if fields[i] == "via" && i+1 < len(fields) {
					gateway = fields[i+1]
				}
				if fields[i] == "dev" && i+1 < len(fields) {
					iface = fields[i+1]
				}
			}
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
				cmd := exec.Command("ip", "route", "add", dest, "via", c.gateway, "dev", c.iface)
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
		cmd := exec.Command("ip", "route", "del", value.(string))
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

	// Get the TUN MTU
	mtu, err := c.device.MTU()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to get TUN MTU: %v", err)
		// Use default MTU if we can't get the actual one
		mtu = 1500
	}

	// Create the annoying padded buffers for WG TUN
	wgBufs := make([][]byte, c.device.BatchSize())
	// Pre-allocate buffers
	for i := range wgBufs {
		wgBufs[i] = make([]byte, 16+mtu)
	}

	// Create the our straight forward buffers for anchor
	bufs := make([][]byte, len(wgBufs))
	// Link the WG TUN buffers to the anchor buffers
	for i := range bufs {
		bufs[i] = wgBufs[i][16:]
	}

	for {
		select {
		case <-c.anchor.Ctx.Done():
			veilnet.Logger.Sugar().Info("Conflux ingress stopped")
			return
		default:
			n := c.anchor.Read(bufs, c.device.BatchSize())
			if n > 0 {
				c.device.Write(wgBufs[:n], 16)
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

	// Flush existing IPs first
	cmd := exec.Command("ip", "addr", "flush", "dev", "veilnet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to clear existing IPs: %s", string(out))
		return fmt.Errorf("failed to clear existing IPs: %s", string(out))
	}

	// Set the IP address
	cmd = exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", ip, netmask), "dev", "veilnet")
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to set IP address: %s", string(out))
		return fmt.Errorf("failed to set IP address: %s", string(out))
	}
	veilnet.Logger.Sugar().Infof("Set VeilNet TUN IP address to %s/%s", ip, netmask)

	// Set the interface up
	cmd = exec.Command("ip", "link", "set", "up", "veilnet")
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to set interface up: %s", string(out))
		return fmt.Errorf("failed to set interface up: %s", string(out))
	}
	veilnet.Logger.Sugar().Infof("Set VeilNet TUN interface to up")

	// // Add Plane Local Network Route
	// c.anchor.PlaneNetworks.Range(func(key, value interface{}) bool {
	// 	cmd = exec.Command("ip", "route", "add", value.(veilnet.PlaneNetwork).Subnet, "via", ip, "dev", "veilnet")
	// 	out, err = cmd.CombinedOutput()
	// 	if err != nil {
	// 		veilnet.Logger.Sugar().Errorf("failed to set plane local network route: %s", string(out))
	// 		return true
	// 	}
	// 	veilnet.Logger.Sugar().Infof("Set plane local network route for %s", value.(veilnet.PlaneNetwork).Subnet)
	// 	return true
	// })

	go func() {
		for {
			select {
			case <-c.anchor.Ctx.Done():
				return
			case subnet := <-c.anchor.PlaneNetworksAddQueue:
				cmd := exec.Command("ip", "route", "add", subnet, "via", ip, "dev", "veilnet")
				out, err := cmd.CombinedOutput()
				if err != nil {
					veilnet.Logger.Sugar().Warnf("failed to set plane local network route: %s", string(out))
					continue
				}
				veilnet.Logger.Sugar().Infof("Added route for plane local network %s", subnet)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-c.anchor.Ctx.Done():
				return
			case subnet := <-c.anchor.PlaneNetworksRemoveQueue:
				cmd := exec.Command("ip", "route", "del", subnet, "via", ip, "dev", "veilnet")
				out, err := cmd.CombinedOutput()
				if err != nil {
					veilnet.Logger.Sugar().Warnf("failed to remove plane local network route: %s", string(out))
					continue
				}
				veilnet.Logger.Sugar().Infof("Removed route for plane local network %s", subnet)
			}
		}
	}()

	if c.portal {

		// Set iptables FORWARD
		cmd = exec.Command("iptables", "-A", "FORWARD", "-i", "veilnet", "-j", "ACCEPT")
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to set inbound iptables FORWARD rules: %s", string(out))
			return fmt.Errorf("failed to set inbound iptables FORWARD rules: %s", string(out))
		}
		cmd = exec.Command("iptables", "-A", "FORWARD", "-o", "veilnet", "-j", "ACCEPT")
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to set outbound iptables FORWARD rules: %s", string(out))
			return fmt.Errorf("failed to set outbound iptables FORWARD rules: %s", string(out))
		}
		veilnet.Logger.Sugar().Infof("Updated iptables FORWARD rules for VeilNet TUN")

		// Set up NAT
		cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", c.iface, "-j", "MASQUERADE")
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to set NAT rules: %s", string(out))
			return fmt.Errorf("failed to set NAT rules: %s", string(out))
		}
		veilnet.Logger.Sugar().Infof("Set up NAT for VeilNet TUN")

		// Check if IP forwarding is already enabled
		cmd = exec.Command("sysctl", "-n", "net.ipv4.ip_forward")
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to check IP forwarding status: %s", string(out))
			return fmt.Errorf("failed to check IP forwarding status: %s", string(out))
		}
		c.ipForwardEnabled = strings.TrimSpace(string(out)) == "1"

		if !c.ipForwardEnabled {
			// Enable IP forwarding
			cmd = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
			out, err = cmd.CombinedOutput()
			if err != nil {
				veilnet.Logger.Sugar().Errorf("failed to enable IP forwarding: %s", string(out))
				return fmt.Errorf("failed to enable IP forwarding: %s", string(out))
			}
			veilnet.Logger.Sugar().Infof("IP forwarding enabled")
		} else {
			veilnet.Logger.Sugar().Infof("IP forwarding already enabled")
		}

	} else {
		// Delete the default route
		cmd = exec.Command("ip", "route", "del", "default", "via", c.gateway, "dev", c.iface)
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("Failed to delete default route: %s", string(out))
			return fmt.Errorf("failed to delete default route: %s", string(out))
		}

		// Add the default route with high metric
		cmd = exec.Command("ip", "route", "add", "default", "via", c.gateway, "dev", c.iface, "metric", "50")
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("Failed to add default route: %s", string(out))
			return fmt.Errorf("failed to add default route: %s", string(out))
		}
		veilnet.Logger.Sugar().Infof("Altered host default route via %s on %s with metric 50", c.gateway, c.iface)

		// Set the TUN interface as the default route
		cmd = exec.Command("ip", "route", "add", "default", "dev", "veilnet")
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("Failed to set default route: %s", string(out))
			return fmt.Errorf("failed to set default route: %s", string(out))
		}
		veilnet.Logger.Sugar().Infof("Set veilnet as default route")

	}

	return nil
}

// CleanHostConfiguraions removes the iptables FORWARD rules and NAT rule for the TUN interface
// It also disables IP forwarding if it was not enabled
func (c *conflux) CleanHostConfiguraions() {

	if c.portal {

		// Remove iptables FORWARD rules
		cmd := exec.Command("iptables", "-D", "FORWARD", "-i", "veilnet", "-j", "ACCEPT")
		out, err := cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Debugf("failed to remove inbound iptables FORWARD rule: %s", string(out))
		} else {
			veilnet.Logger.Sugar().Infof("Removed inbound iptables FORWARD rule")
		}

		cmd = exec.Command("iptables", "-D", "FORWARD", "-o", "veilnet", "-j", "ACCEPT")
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Debugf("failed to remove outbound iptables FORWARD rule: %s", string(out))
		} else {
			veilnet.Logger.Sugar().Infof("Removed outbound iptables FORWARD rule")
		}

		// Remove NAT rule
		cmd = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", c.iface, "-j", "MASQUERADE")
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Debugf("failed to remove NAT rule: %s", string(out))
		} else {
			veilnet.Logger.Sugar().Infof("Removed NAT rule")
		}

		// Disable IP forwarding if it was not enabled
		if !c.ipForwardEnabled {
			cmd = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0")
			out, err = cmd.CombinedOutput()
			if err != nil {
				veilnet.Logger.Sugar().Debugf("failed to disable IP forwarding: %s", string(out))
			} else {
				veilnet.Logger.Sugar().Infof("Disabled IP forwarding")
			}
		}

	} else {
		// Remove veilnet TUN as default route
		cmd := exec.Command("ip", "route", "del", "default", "dev", "veilnet")
		out, err := cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Debugf("failed to remove veilnet TUN as default route: %s", string(out))
		} else {
			veilnet.Logger.Sugar().Infof("Removed veilnet TUN as default route")
		}

		// Delete the altered host default route
		cmd = exec.Command("ip", "route", "del", "default", "via", c.gateway, "dev", c.iface)
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Debugf("failed to delete altered host default route: %s", string(out))
		} else {
			veilnet.Logger.Sugar().Infof("Removed altered host default route")
		}

		// Restore the host default route
		cmd = exec.Command("ip", "route", "add", "default", "via", c.gateway, "dev", c.iface)
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Debugf("failed to restore default route on host: %s", string(out))
		} else {
			veilnet.Logger.Sugar().Infof("Restored default route on host")
		}
	}
}
