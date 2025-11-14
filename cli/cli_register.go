package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type Register struct {
	Tag      string `help:"The tag for the conflux" env:"VEILNET_CONFLUX_TAG" json:"tag"`
	Cidr     string `help:"The CIDR of the conflux" env:"VEILNET_CONFLUX_CIDR" json:"cidr"`
	Token    string `short:"t" help:"The registration token" env:"VEILNET_REGISTRATION_TOKEN" json:"registration_token"`
	Guardian string `short:"g" help:"The Guardian URL (Authentication Server), default: https://guardian.veilnet.app" default:"https://guardian.veilnet.app" env:"VEILNET_GUARDIAN" json:"guardian"`
	Portal   bool   `short:"p" help:"Enable portal mode, default: false" default:"false" env:"VEILNET_PORTAL" json:"portal"`
	Teams    string `help:"The teams to be forwarded by the conflux, separated by comma, e.g. team1,team2" env:"VEILNET_CONFLUX_TEAMS" json:"teams"`
	ID       string `kong:"-" json:"id"`
}

func (cmd *Register) Run() error {
	baseURL, err := url.Parse("http://localhost:1993")
	if err != nil {
		return fmt.Errorf("failed to parse base URL: %v", err)
	}

	baseURL.Path = "/register"

	body, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", baseURL.String(), bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		return fmt.Errorf("failed to register conflux: %s: %s", resp.Status, string(body))
	}

	return nil
}
