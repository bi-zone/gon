// Package notarize notarizes packages with Apple.
package notarize

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
)

// Options are the options for notarization.
type Options struct {
	// File is the file to notarize. This must be in zip, dmg, or pkg format.
	File string

	// DeveloperId is your Apple Developer Apple ID.
	DeveloperId string

	// Password is your Apple Connect password. This must be specified.
	// This also supports `@keychain:<value>` and `@env:<value>` formats to
	// read from the keychain and environment variables, respectively.
	Password string

	// Provider is the Apple Connect provider to use. This is optional
	// and is only used for Apple Connect accounts that support multiple
	// providers.
	Provider string

	// ApiKey is the name of a API key generated on App Store Connect portal.
	ApiKey string

	// ApiKeyPath specifies an absolute path to the `.p8` file related to the ApiKey.
	// (Refer to `xcrun altool --help` for more info about API key format).
	ApiKeyPath string

	// ApiIssuer is the ID of the specified ApiKey Issuer. Required if ApiKey is specified.
	ApiIssuer string

	// UploadLock, if specified, will limit concurrency when uploading
	// packages. The notary submission process does not allow concurrent
	// uploads of packages with the same bundle ID, it appears. If you set
	// this lock, we'll hold the lock while we upload.
	UploadLock *sync.Mutex

	// Status, if non-nil, will be invoked with status updates throughout
	// the notarization process.
	Status Status

	// Logger is the logger to use. If this is nil then no logging will be done.
	Logger hclog.Logger

	// BaseCmd is the base command for executing app submission. This is
	// used for tests to overwrite where the codesign binary is. If this isn't
	// specified then we use `xcrun notarytool` as the base.
	BaseCmd *exec.Cmd

	// PollingInterval defines how often `gon` will poll the notarization status.
	// Apple Connect API has some kind of opaque (at least when we use altool)
	// rate limiting so try to set the interval reasonable low. If `nil` --
	// default interval will be used.
	PollingInterval *time.Duration
}

// AuthArgs returns `xcrun notarytool` authentication arguments using provided
// `Username+Password` or `ApiKey+ApiIssuer`. API authentication takes
// precedence over password authentication. Returns error when can't select
// an authentication method.
func (o Options) AuthArgs() ([]string, error) {
	switch {
	case o.ApiKey != "" && o.ApiIssuer != "":
		if o.ApiKeyPath == "" {
			var err error
			o.ApiKeyPath, err = guessApiKeyFile(o.ApiKey)
			if err != nil {
				return nil, fmt.Errorf("%w. %s",
					err, "Please specify api_key_path or put a key into default altool location")
			}
		}
		return []string{
			"--key-id", o.ApiKey,
			"--issuer", o.ApiIssuer,
			"--key", o.ApiKeyPath,
		}, nil
	case o.DeveloperId != "" && o.Password != "":
		return []string{
			"--apple-id", o.DeveloperId,
			"--password", o.Password,
		}, nil
	default:
		return nil, fmt.Errorf("no authorization info given. " +
			"Please specify Apple username + password or api_key + api_issuer")
	}
}

// Notarize performs the notarization process for macOS applications. This
// will block for the duration of this process which can take many minutes.
// The Status field in Options can be used to get status change notifications.
//
// This will return the notarization info and an error if any occurred.
// The Info result _may_ be non-nil in the presence of an error and can be
// used to gather more information about the notarization attempt.
//
// If error is nil, then Info is guaranteed to be non-nil.
// If error is not nil, notarization failed and Info _may_ be non-nil.
func Notarize(ctx context.Context, opts *Options) (*Info, *Log, error) {
	logger := opts.Logger
	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	status := opts.Status
	if status == nil {
		status = noopStatus{}
	}

	lock := opts.UploadLock
	if lock == nil {
		lock = &sync.Mutex{}
	}

	pollInterval := 30 * time.Second
	if opts.PollingInterval != nil {
		pollInterval = *opts.PollingInterval
	}

	// First perform the upload
	lock.Lock()
	status.Submitting()
	uuid, err := upload(ctx, opts)
	lock.Unlock()
	if err != nil {
		return nil, nil, err
	}
	status.Submitted(uuid)

	// Begin polling the info. The first thing we wait for is for the status
	// _to even exist_. While we get an error requesting info with an error
	// code of 1519 (UUID not found), then we are stuck in a queue. Sometimes
	// this queue is hours long. We just have to wait.
	infoResult := &Info{RequestUUID: uuid}
	for {
		time.Sleep(pollInterval)
		_, err := info(ctx, infoResult.RequestUUID, opts)
		if err == nil {
			break
		}

		// If we got error code 1519 that means that the UUID was not found.
		// This means we're in a queue.
		if e, ok := err.(Errors); ok && e.ContainsCode(1519) {
			continue
		}

		// A real error, just return that
		return infoResult, nil, err
	}

	// Now that the UUID result has been found, we poll more quickly
	// waiting for the analysis to complete. This usually happens within
	// minutes.
	for {
		// Update the info. It is possible for this to return a nil info,
		// and we don't ever want to set result to nil, so we have a check.
		newInfoResult, err := info(ctx, infoResult.RequestUUID, opts)
		if newInfoResult != nil {
			infoResult = newInfoResult
		}

		if err != nil {
			// This code is the network became unavailable error. If this
			// happens then we just log and retry.
			if e, ok := err.(Errors); ok && e.ContainsCode(-19000) {
				logger.Warn("error that network became unavailable, will retry")
				goto RETRYINFO
			}

			return infoResult, nil, err
		}

		status.InfoStatus(*infoResult)

		// If we reached a terminal state then exit
		if infoResult.Status == "Accepted" || infoResult.Status == "Invalid" {
			break
		}

	RETRYINFO:
		// Sleep, we just do a constant poll every 5 seconds. I haven't yet
		// found any rate limits to the service so this seems okay.
		time.Sleep(5 * time.Second)
	}

	logResult := &Log{JobId: uuid}
	for {
		// Update the log. It is possible for this to return a nil log,
		// and we don't ever want to set result to nil, so we have a check.
		newLogResult, err := log(ctx, logResult.JobId, opts)
		if newLogResult != nil {
			logResult = newLogResult
		}

		if err != nil {
			// This code is the network became unavailable error. If this
			// happens then we just log and retry.
			if e, ok := err.(Errors); ok && e.ContainsCode(-19000) {
				logger.Warn("error that network became unavailable, will retry")
				goto RETRYLOG
			}

			return infoResult, logResult, err
		}

		status.LogStatus(*logResult)

		// If we reached a terminal state then exit
		if logResult.Status == "Accepted" || logResult.Status == "Invalid" {
			break
		}

	RETRYLOG:
		// Sleep, we just do a constant poll every 5 seconds. I haven't yet
		// found any rate limits to the service so this seems okay.
		time.Sleep(pollInterval)
	}

	// If we're in an invalid status then return an error
	err = nil
	if logResult.Status == "Invalid" && infoResult.Status == "Invalid" {
		err = fmt.Errorf("package is invalid.")
	}

	return infoResult, logResult, err
}

func guessApiKeyFile(apiKey string) (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("can't resolve homedir: %w", err)
	}

	// `xcrun altool --help` -- apiKey param comment.
	altoolDefaultDirs := []string{
		"./private_keys",
		"~/private_keys",
		"~/.private_keys",
		"~/.appstoreconnect/private_keys",
	}
	if envDir := os.Getenv("API_PRIVATE_KEYS_DIR"); envDir != "" {
		altoolDefaultDirs = []string{envDir}
	}

	keyName := "AuthKey_" + apiKey + ".p8"
	for _, dir := range altoolDefaultDirs {
		if strings.HasPrefix(dir, "~/") {
			dir = filepath.Join(usr.HomeDir, dir[2:])
		}
		path := filepath.Join(dir, keyName)
		if s, err := os.Stat(path); err == nil && s.Mode().IsRegular() {
			return path, nil
		}
	}
	return "", fmt.Errorf("can't found an API key file in default dirs")
}
