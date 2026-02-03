// Package logger provides the global zap logger for the application.
package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is the global zap logger.
// Use Logger.Sugar() to get a SugaredLogger which supports Infof, Errorf, etc.
var Logger *zap.Logger

// init initializes the development zap config with colors and ISO8601 time format.
//
// Inputs: none.
//
// Outputs: none. Panics if the zap config cannot be built.
func init() {
	// Configure Zap for development with colors
	config := zap.NewDevelopmentConfig()

	// Enable automatic color for levels (INFO, ERROR, etc.)
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	// Use a human-readable ISO8601 time format
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	// Disable caller information (file:line)
	config.DisableCaller = true
	// Disable stacktrace
	config.DisableStacktrace = true

	var err error
	Logger, err = config.Build()
	if err != nil {
		// Fallback if zap fails to initialize
		panic(err)
	}
}
