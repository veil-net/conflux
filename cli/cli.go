package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/alecthomas/kong"
	"github.com/veil-net/veilnet"
)

type CLI struct {
	Version kong.VersionFlag `short:"v" help:"Print the version and exit"`
	Run     Run              `cmd:"run" default:"true" help:"Run the conflux service"`
	Install Install          `cmd:"install" help:"Install the conflux service"`
	Start   Start            `cmd:"start" help:"Start the conflux service"`
	Stop    Stop             `cmd:"stop" help:"Stop the conflux service"`
	Remove  Remove           `cmd:"remove" help:"Remove the conflux service"`
	Status  Status           `cmd:"status" help:"Get the status of the conflux service"`
	Docker  Docker           `cmd:"docker" help:"Run the conflux service in docker"`

	Register   Register   `cmd:"register" help:"Register a new conflux with a registration token, and start the conflux"`
	Unregister Unregister `cmd:"unregister" help:"Unregister the conflux and stop the service"`
	Up         Up         `cmd:"up" help:"Start the conflux with a conflux token"`
	Down       Down       `cmd:"down" help:"Stop the conflux"`
}

type Run struct{}

func (cmd *Run) Run() error {
	conflux := NewConflux()
	err := conflux.Run()
	if err != nil {
		return err
	}
	return nil
}

type Install struct{}

func (cmd *Install) Run() error {
	conflux := NewConflux()
	err := conflux.Install()
	if err != nil {
		return err
	}
	return nil
}

type Start struct{}

func (cmd *Start) Run() error {
	conflux := NewConflux()
	err := conflux.Start()
	if err != nil {
		return err
	}
	return nil
}

type Stop struct{}

func (cmd *Stop) Run() error {
	conflux := NewConflux()
	err := conflux.Stop()
	if err != nil {
		return err
	}
	return nil
}

type Remove struct{}

func (cmd *Remove) Run() error {
	conflux := NewConflux()
	err := conflux.Remove()
	if err != nil {
		return err
	}
	return nil
}

type Status struct{}

func (cmd *Status) Run() error {
	conflux := NewConflux()
	status, err := conflux.Status()
	if err != nil {
		return err
	}
	if status {
		veilnet.Logger.Sugar().Infof("VeilNet service is running.")
		return nil
	} else {
		veilnet.Logger.Sugar().Errorf("VeilNet service is not running.")
		return fmt.Errorf("VeilNet service is not running")
	}
}

type Docker struct{
	Tag      string `help:"The tag for the conflux" env:"VEILNET_CONFLUX_TAG" json:"tag"`
	Cidr     string `help:"The CIDR of the conflux" env:"VEILNET_CONFLUX_CIDR" json:"cidr"`
	Token    string `short:"t" help:"The registration token" env:"VEILNET_REGISTRATION_TOKEN" json:"registration_token"`
	Guardian string `short:"g" help:"The Guardian URL (Authentication Server), default: https://guardian.veilnet.app" default:"https://guardian.veilnet.app" env:"VEILNET_GUARDIAN" json:"guardian"`
	Teams    string `help:"The teams to be forwarded by the conflux, separated by comma, e.g. team1,team2" env:"VEILNET_CONFLUX_TEAMS" json:"teams"`
	Portal   bool   `short:"p" help:"Enable portal mode, default: false" default:"false" env:"VEILNET_PORTAL" json:"portal"`
}

func (cmd *Docker) Run() error {
	// Parse the Guardian URL
	path := fmt.Sprintf("%s/conflux/register", cmd.Guardian)

	// Marshal the request body
	body, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	// Create the request
	req, err := http.NewRequest("POST", path, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set the Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cmd.Token))
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse the response body
	var confluxToken ConfluxToken
	err = json.Unmarshal(body, &confluxToken)
	if err != nil {
		return fmt.Errorf("failed to parse response body: %v", err)
	}

	conflux := NewConflux()
	err = conflux.StartVeilNet(cmd.Guardian, confluxToken.Token, cmd.Portal)
	if err != nil {
		return fmt.Errorf("failed to start VeilNet: %v", err)
	}
	
	anchor := conflux.GetAnchor()
	<-anchor.Ctx.Done()
	return nil
}
