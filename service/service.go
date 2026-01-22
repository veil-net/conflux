package service

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/veil-net/conflux/logger"
)

var Logger = logger.Logger

type Service interface {
	Run() error
	Install() error
	Start() error
	Stop() error
	Remove() error
	Status() error
}

func NewService() Service {
	return newService()
}

func ExecuteCmd(cmd ...string) error {
	command := exec.Command(cmd[0], cmd[1:]...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		return fmt.Errorf("failed to execute command %s, error: %w", cmd, err)
	}
	return nil
}