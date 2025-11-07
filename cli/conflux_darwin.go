//go:build darwin
// +build darwin

package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/veil-net/veilnet"
	tun "golang.zx2c4.com/wireguard/tun"
)

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
	return nil
}

func (c *conflux) Start() error {
	return nil
}

func (c *conflux) Stop() error {
	return nil
}

func (c *conflux) Remove() error {
	return nil
}

func (c *conflux) Status() (bool, error) {
	return false, nil
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
	err = c.anchor.Start(apiBaseURL, anchorToken, false)
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

	cmd := exec.Command("route", "-n", "get", "default")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to get default route: %s", string(out))
		return err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			c.gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
		if strings.HasPrefix(line, "interface:") {
			c.iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}

	if c.gateway == "" || c.iface == "" {
		err = fmt.Errorf("default gateway or interface not found")
		veilnet.Logger.Sugar().Errorf("Host default gateway or interface not found")
		return err
	}

	veilnet.Logger.Sugar().Infof("Found Host Default gateway: %s via interface %s", c.gateway, c.iface)
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
				cmd := exec.Command("route", "-n", "add", dest, c.gateway, "-interface", c.iface)
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
		cmd := exec.Command("route", "-n", "del", value.(string))
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

	// Bring the interface up
	cmd := exec.Command("ifconfig", "veilnet", "up")
	out, err := cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to bring interface veilnet up: %s", string(out))
		return err
	}
	veilnet.Logger.Sugar().Infof("Set VeilNet TUN interface up")

	// Set the IP address and netmask
	cmd = exec.Command("ifconfig", "veilnet", "inet", ip, "netmask", c.convertNetmask(netmask))
	out, err = cmd.CombinedOutput()
	if err != nil {
		veilnet.Logger.Sugar().Errorf("failed to set IP %s/%s on veilnet: %s", ip, netmask, string(out))
		return err
	}
	veilnet.Logger.Sugar().Infof("Set VeilNet TUN IP to %s/%s", ip, netmask)

	// // Add Plane Local Network Route
	// c.anchor.PlaneNetworks.Range(func(key, value interface{}) bool {
	// 	cmd := exec.Command("route", "-n", "add", value.(veilnet.PlaneNetwork).Subnet, "via", c.gateway, "dev", c.iface)
	// 	out, err := cmd.CombinedOutput()
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

				cmd := exec.Command("route", "-n", "add", subnet, "via", ip, "dev", "veilnet")
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
				cmd := exec.Command("route", "-n", "del", subnet, "via", ip, "dev", "veilnet")
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
		// Delete the original default route
		cmd = exec.Command("route", "-n", "delete", "default")
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to delete original default route: %s", string(out))
			return err
		}
		veilnet.Logger.Sugar().Infof("Deleted original default route")

		// Recreate the original default route with higher hopcount (lower priority)
		cmd = exec.Command("route", "-n", "add", "default", c.gateway, "-hopcount", "10")
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to recreate default route with higher hopcount: %s", string(out))
			return err
		}
		veilnet.Logger.Sugar().Infof("Recreated default route with hopcount 10")

		// Add a route through the TUN interface with lower hopcount (higher priority)
		cmd = exec.Command("route", "-n", "add", "default", "-interface", "veilnet", "-hopcount", "5")
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Errorf("failed to set default route: %s", string(out))
			return err
		}
		veilnet.Logger.Sugar().Infof("Set veilnet as default route with hopcount 5")
	}

	return nil
}

// convertNetmask converts CIDR notation to dotted decimal notation
func (c *conflux) convertNetmask(cidr string) string {
	switch cidr {
	case "8":
		return "255.0.0.0"
	case "16":
		return "255.255.0.0"
	case "24":
		return "255.255.255.0"
	case "32":
		return "255.255.255.255"
	default:
		return "255.255.255.0" // Default to /24
	}
}

// CleanHostConfiguraions removes the iptables FORWARD rules and NAT rule for the TUN interface
// It also disables IP forwarding if it was not enabled
func (c *conflux) CleanHostConfiguraions() {

	if !c.portal {
		// Delete the route through the TUN interface
		cmd := exec.Command("route", "-n", "delete", "default", "-interface", "veilnet")
		out, err := cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Debugf("failed to delete TUN default route: %s", string(out))
		} else {
			veilnet.Logger.Sugar().Infof("Deleted TUN default route")
		}

		// Delete the altered default route
		cmd = exec.Command("route", "-n", "delete", "default")
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Debugf("failed to delete altered default route: %s", string(out))
		} else {
			veilnet.Logger.Sugar().Infof("Deleted altered default route")
		}

		// Restore the original host default route
		cmd = exec.Command("route", "-n", "add", "default", c.gateway)
		out, err = cmd.CombinedOutput()
		if err != nil {
			veilnet.Logger.Sugar().Debugf("failed to restore host default route: %s", string(out))
		} else {
			veilnet.Logger.Sugar().Infof("Restored host default route")
		}
	}
}
