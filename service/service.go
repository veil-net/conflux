package service

import "github.com/veil-net/conflux/logger"

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