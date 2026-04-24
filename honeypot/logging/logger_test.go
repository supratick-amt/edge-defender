package logging_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RootEvidence/honeypot/logging"
	"github.com/stretchr/testify/require"
)

func TestNew_ValidLevel_ReturnsLogger(t *testing.T) {
	logger, err := logging.New("info", "")
	require.NoError(t, err)
	require.NotNil(t, logger)
}

func TestNew_InvalidLevel_ReturnsError(t *testing.T) {
	_, err := logging.New("nonsense", "")
	require.Error(t, err)
}

func TestNew_WritableLogDir_CreatesFileLogger(t *testing.T) {
	dir := t.TempDir()
	logger, err := logging.New("info", dir)
	require.NoError(t, err)
	require.NotNil(t, logger)

	// Log file must exist after logger is constructed.
	_, statErr := os.Stat(filepath.Join(dir, "honeypot.log"))
	require.NoError(t, statErr)
}

func TestNew_UnwritableLogDir_DegradeToStdout(t *testing.T) {
	// Create a dir that the process cannot write to.
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { os.Chmod(dir, 0o755) }) // restore so TempDir cleanup works

	// Must succeed even though the log file cannot be opened.
	logger, err := logging.New("info", dir)
	require.NoError(t, err)
	require.NotNil(t, logger, "expected stdout-only logger on file-open failure")
}
