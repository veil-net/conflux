package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is the global zap logger.
// Use Logger.Sugar() to get a SugaredLogger which supports Infof, Errorf, etc.
var Logger *zap.Logger

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
