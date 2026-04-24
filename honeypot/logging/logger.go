// Package logging builds the zap logger used by the honeypot.
// LOG_LEVEL env var controls verbosity (debug/info/warn/error, default info).
// LOG_DIR env var, when set, writes JSON logs to that directory in addition to stdout.
package logging

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New returns a production-style JSON zap logger. If logDir is non-empty, log
// lines are also written to logDir/honeypot.log.
func New(level, logDir string) (*zap.Logger, error) {
	zapLevel, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	// Always write to stdout.
	cores := []zapcore.Core{
		zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderCfg),
			zapcore.AddSync(os.Stdout),
			zapLevel,
		),
	}

	if logDir != "" {
		if err := os.MkdirAll(logDir, 0o755); err != nil {
			return nil, fmt.Errorf("create log dir %s: %w", logDir, err)
		}
		f, err := os.OpenFile(
			filepath.Join(logDir, "honeypot.log"),
			os.O_CREATE|os.O_APPEND|os.O_WRONLY,
			0o644,
		)
		if err != nil {
			// Degrade gracefully: warn on stdout-only logger and continue.
			// Common cause: container bind-mount directory owned by host UID.
			stdoutLogger := zap.New(zapcore.NewTee(cores...))
			stdoutLogger.Warn("file logging disabled: cannot open log file",
				zap.String("path", filepath.Join(logDir, "honeypot.log")),
				zap.Error(err))
			return stdoutLogger, nil
		}
		cores = append(cores, zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderCfg),
			zapcore.AddSync(f),
			zapLevel,
		))
	}

	return zap.New(zapcore.NewTee(cores...)), nil
}

func parseLevel(s string) (zapcore.Level, error) {
	if s == "" {
		return zapcore.InfoLevel, nil
	}
	var l zapcore.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return zapcore.InfoLevel, fmt.Errorf("invalid log level %q: %w", s, err)
	}
	return l, nil
}
