package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// Define color codes
const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorReset  = "\033[0m"
)

// CustomColorEncoder wraps a zapcore.Encoder to provide colored log level output
// in the terminal. It implements custom encoding logic to add ANSI color codes
// to log messages based on their severity level (e.g., red for errors, green for info).
type CustomColorEncoder struct {
	zapcore.Encoder
}

func (c *CustomColorEncoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	_, err := c.Encoder.EncodeEntry(entry, fields)
	if err != nil {
		return nil, err
	}

	// Add color based on log level
	var color string
	switch entry.Level {
	case zapcore.DebugLevel:
		color = colorBlue
	case zapcore.InfoLevel:
		color = colorGreen
	case zapcore.WarnLevel:
		color = colorYellow
	case zapcore.ErrorLevel, zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		color = colorRed
	default:
		color = colorReset
	}

	// Create a new buffer for the custom format
	coloredBuf := buffer.NewPool().Get()
	coloredBuf.AppendString(color)
	coloredBuf.AppendString(entry.Level.CapitalString())
	coloredBuf.AppendString(strings.Repeat(" ", 10-len(entry.Level.CapitalString())))
	coloredBuf.AppendString(entry.Message)
	coloredBuf.AppendString(colorReset)
	coloredBuf.AppendString("\n")
	return coloredBuf, nil
}

// InitializeLogger creates and configures a new zap logger with color-coded output
// for terminal display, and optionally also logs to a file located in the
// current executable's directory when enableFileLog is true.
// It configures a custom encoder that:
// - Adds ANSI colors to log levels (e.g., red for errors, green for info)
// - Formats log entries with consistent spacing and layout
// - Disables timestamp and caller information for cleaner output
// Returns a configured *zap.Logger instance ready for use.
func InitializeLogger(enableFileLog bool) *zap.Logger {
	// Console encoder (colored)
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "",
		LevelKey:       "",
		NameKey:        "",
		CallerKey:      "",
		MessageKey:     "",
		StacktraceKey:  "",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	customEncoder := &CustomColorEncoder{
		Encoder: zapcore.NewConsoleEncoder(encoderConfig),
	}
	consoleCore := zapcore.NewCore(customEncoder, zapcore.AddSync(os.Stdout), zap.InfoLevel)

	if !enableFileLog {
		return zap.New(consoleCore)
	}

	// File encoder (structured, no colors)
	fileEncoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "",
		CallerKey:      "",
		MessageKey:     "msg",
		StacktraceKey:  "",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	fileEncoder := zapcore.NewJSONEncoder(fileEncoderConfig)

	execPath, err := os.Executable()
	if err != nil {
		execPath = "."
	}
	execDir := filepath.Dir(execPath)
	prog := filepath.Base(execPath)
	logPath := filepath.Join(execDir, prog+".log")

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		// Fallback to console-only if file can't be opened
		return zap.New(consoleCore)
	}

	fileCore := zapcore.NewCore(fileEncoder, zapcore.AddSync(f), zap.InfoLevel)

	// Tee to both console and file
	return zap.New(zapcore.NewTee(consoleCore, fileCore))
}

// Logger is the package's global logger instance that provides colored logging output.
// It is automatically initialized when the package is imported and can be accessed
// by other packages for consistent logging behavior.
var Logger *zap.Logger

func init() {
	// Default to enabling file log; set to false for console-only
	Logger = InitializeLogger(false)
}

// DisableDebug increases the minimum logging level to InfoLevel, effectively
// filtering out all debug messages while still showing info, warning, and error logs.
// Returns an error if the global Logger has not been properly initialized.
func DisableDebug() error {
	if Logger == nil {
		return fmt.Errorf("logger not initialized")
	}
	Logger = Logger.WithOptions(zap.IncreaseLevel(zap.InfoLevel))
	return nil
}
