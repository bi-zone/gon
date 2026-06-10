package notarize

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"howett.net/plist"
)

// upload submits the file for notarization and returns the request UUID
// or an error.
func upload(ctx context.Context, opts *Options) (string, error) {
	logger := opts.Logger
	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	// Resolve the tool path and env, honoring a BaseCmd override (used by tests).
	var base exec.Cmd
	if opts.BaseCmd != nil {
		base = *opts.BaseCmd
	}
	if base.Path == "" {
		path, err := exec.LookPath("xcrun")
		if err != nil {
			return "", err
		}
		base.Path = path
	}

	args := []string{
		"notarytool",
		"submit", opts.File,
		"--output-format", "plist",
	}
	if opts.Provider != "" {
		args = append(args, "--team-id", opts.Provider)
	}

	auth, err := opts.AuthArgs()
	if err != nil {
		return "", err
	}
	args = append(args, auth...)

	// Build a context-aware command so a cancelled ctx kills the process.
	cmd := exec.CommandContext(ctx, base.Path, args...)
	cmd.Args[0] = filepath.Base(base.Path)
	cmd.Env = base.Env

	// We store all output in out for logging and in case there is an error
	var out, combined bytes.Buffer
	cmd.Stdout = io.MultiWriter(&out, &combined)
	cmd.Stderr = &combined

	// Log what we're going to execute
	logger.Info("submitting file for notarization",
		"file", opts.File,
		"command_path", cmd.Path,
		"command_args", cmd.Args,
	)

	// Execute
	err = cmd.Run()

	// Log the result
	logger.Info("notarization submission complete",
		"output", out.String(),
		"err", err,
	)

	// If we have any output, try to decode that since even in the case of
	// an error it will output some information.
	var result uploadResult
	if out.Len() > 0 {
		if _, perr := plist.Unmarshal(out.Bytes(), &result); perr != nil {
			return "", fmt.Errorf("failed to decode notarization submission output: %w", perr)
		}
	}

	// Now we check the error for actually running the process
	if err != nil {
		return "", fmt.Errorf("error submitting for notarization:\n\n%s", combined.String())
	}

	// We should have a request UUID set at this point since we checked for errors
	if result.RequestUUID == "" {
		return "", fmt.Errorf(
			"notarization appeared to succeed, but we failed at parsing " +
				"the request UUID. Please enable logging, try again, and report " +
				"this as a bug")
	}

	logger.Info("notarization request submitted", "request_id", result.RequestUUID)
	return result.RequestUUID, nil

}

// uploadResult is the plist structure when the upload succeeds
type uploadResult struct {
	// Upload is non-nil if there is a successful upload
	RequestUUID string `plist:"id"`
}
