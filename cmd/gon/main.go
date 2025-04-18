package main

import (
	"context"
	"debug/buildinfo"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"

	"github.com/bi-zone/gon/internal/config"
	"github.com/bi-zone/gon/package/dmg"
	"github.com/bi-zone/gon/package/zip"
	"github.com/bi-zone/gon/sign"
)

// Set by build process
var (
	version string
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	// Look for version
	for _, v := range os.Args[1:] {
		v = strings.TrimLeft(v, "-")
		if v == "v" || v == "version" {
			if version == "" {
				if v, err := parseVersion(); err == nil && v != "" {
					version = v
				} else {
					version = "dev"
				}
			}

			fmt.Printf("bi-zone/gon version %s\n", version)
			return 0
		}
	}

	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	logJSON := flags.Bool("log-json", false, "Output logs in JSON format for machine readability.")
	logLevel := flags.String("log-level", "", "Log level to output. Defaults to no logging.")
	dontNotarize := flags.Bool("dont-notarize", false, "Do all the defined steps except notarization.")
	pollInterval := flags.Duration("poll-interval", 30*time.Second, "Specify interval for notarization polling.")
	flags.Parse(os.Args[1:])
	args := flags.Args()

	// Build a logger
	logOut := ioutil.Discard
	if *logLevel != "" {
		logOut = os.Stderr
	}
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.LevelFromString(*logLevel),
		Output:     logOut,
		JSONFormat: *logJSON,
	})

	// We expect a configuration file
	if len(args) != 1 {
		fmt.Fprintf(os.Stdout, color.RedString("❗️ Path to configuration expected.\n\n"))
		printHelp(flags)
		return 1
	}

	// Parse the configuration
	cfg, err := config.ParseFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stdout, color.RedString("❗️ Error loading configuration:\n\n%s\n", err))
		return 1
	}

	// The files to notarize should be added to this. We'll submit one notarization
	// request per file here.
	var items []*item

	// A bunch of validation
	if len(cfg.Source) > 0 {
		if cfg.BundleId == "" {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout,
				"❗️ `bundle_id` configuration required with `source` set\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"When you set the `source` configuration, you must also specify the\n"+
					"`bundle_id` that will be used for packaging and notarization.\n")
			return 1
		}

		if cfg.Sign == nil {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout,
				"❗️ `sign` configuration required with `source` set\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"When you set the `source` configuration, you must also specify the\n"+
					"`sign` configuration to sign the input files.\n")
			return 1
		}
	} else {
		if len(cfg.Notarize) == 0 {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout, "❗️ No source files specified\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"Your configuration had an empty 'source' and empty 'notarize' values. This must be populated with\n"+
					"at least one file to sign, package, and notarize.\n")
			return 1
		}

		if cfg.Zip != nil {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout,
				"❗️ `zip` can only be set while `source` is also set\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"Zip packaging is only supported when `source` is specified. This is\n"+
					"because the `zip` option packages the source files. If there are no\n"+
					"source files specified, then there is nothing to package.\n")
			return 1
		}

		if cfg.Dmg != nil {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout,
				"❗️ `dmg` can only be set while `source` is also set\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"Dmg packaging is only supported when `source` is specified. This is\n"+
					"because the `dmg` option packages the source files. If there are no\n"+
					"source files specified, then there is nothing to package.\n")
			return 1
		}
	}

	// Notarize is an alternative to "Source", where you specify
	// a single .pkg or .zip that is ready for notarization and stapling
	if len(cfg.Notarize) > 0 {
		for _, c := range cfg.Notarize {
			items = append(items, &item{
				Path:     c.Path,
				BundleId: c.BundleId,
				Staple:   c.Staple,
			})
		}
	}

	// If not specified in the configuration, we initialize a new struct that we'll
	// load with values from the environment.
	if cfg.AppleId == nil {
		cfg.AppleId = &config.AppleId{}
	}
	if !*dontNotarize {
		if ret := validateAndSetEnv(cfg.AppleId); ret != 0 {
			return ret
		}
	}

	// If we're in source mode, then sign & package as configured
	if len(cfg.Source) > 0 {
		if cfg.Sign != nil {
			// Perform codesigning
			color.New(color.Bold).Fprintf(os.Stdout, "==> %s  Signing files...\n", iconSign)
			err = sign.Sign(context.Background(), &sign.Options{
				Files:        cfg.Source,
				Identity:     cfg.Sign.ApplicationIdentity,
				Entitlements: cfg.Sign.EntitlementsFile,
				Logger:       logger.Named("sign"),
			})
			if err != nil {
				fmt.Fprintf(os.Stdout, color.RedString("❗️ Error signing files:\n\n%s\n", err))
				return 1
			}
			color.New(color.Bold, color.FgGreen).Fprintf(os.Stdout, "    Code signing successful\n")
		}

		// Create a zip
		if cfg.Zip != nil {
			color.New(color.Bold).Fprintf(os.Stdout, "==> %s  Creating Zip archive...\n", iconPackage)
			err = zip.Zip(context.Background(), &zip.Options{
				Files:      cfg.Source,
				OutputPath: cfg.Zip.OutputPath,
			})
			if err != nil {
				fmt.Fprintf(os.Stdout, color.RedString("❗️ Error creating zip archive:\n\n%s\n", err))
				return 1
			}
			color.New(color.Bold, color.FgGreen).Fprintf(os.Stdout, "    Zip archive created with signed files\n")

			// Queue to notarize
			items = append(items, &item{Path: cfg.Zip.OutputPath})
		}

		// Create a dmg
		if cfg.Dmg != nil && cfg.Sign != nil {
			// First create the dmg itself. This passes in the signed files.
			color.New(color.Bold).Fprintf(os.Stdout, "==> %s  Creating dmg...\n", iconPackage)
			color.New().Fprintf(os.Stdout, "    This will open Finder windows momentarily.\n")
			err = dmg.Dmg(context.Background(), &dmg.Options{
				Files:              cfg.Source,
				OutputPath:         cfg.Dmg.OutputPath,
				VolumeName:         cfg.Dmg.VolumeName,
				SkipPrettification: cfg.Dmg.SkipPrettification,
				Logger:             logger.Named("dmg"),
			})
			if err != nil {
				fmt.Fprintf(os.Stdout, color.RedString("❗️ Error creating dmg:\n\n%s\n", err))
				return 1
			}
			color.New().Fprintf(os.Stdout, "    Dmg file created: %s\n", cfg.Dmg.OutputPath)

			// Next we need to sign the actual DMG as well
			color.New().Fprintf(os.Stdout, "    Signing dmg...\n")
			err = sign.Sign(context.Background(), &sign.Options{
				Files:    []string{cfg.Dmg.OutputPath},
				Identity: cfg.Sign.ApplicationIdentity,
				Logger:   logger.Named("dmg"),
			})
			if err != nil {
				fmt.Fprintf(os.Stdout, color.RedString("❗️ Error signing dmg:\n\n%s\n", err))
				return 1
			}
			color.New(color.Bold, color.FgGreen).Fprintf(os.Stdout, "    Dmg created and signed\n")

			// Queue to notarize
			items = append(items, &item{Path: cfg.Dmg.OutputPath, Staple: true})
		}
	}

	// If a user wants just to sign and/or package an app -- return here.
	if *dontNotarize {
		return 0
	}

	// If we have no items to notarize and DontNotarize isn't set then its probably an error in the configuration.
	if len(items) == 0 {
		color.New(color.Bold, color.FgYellow).Fprintf(os.Stdout, "\n⚠️  No items to notarize\n")
		color.New(color.FgYellow).Fprintf(os.Stdout,
			"You must specify a 'notarize' section or a 'source' section plus a 'zip' or 'dmg' section "+
				"in your configuration to enable packaging and notarization. Without these sections, gon\n"+
				"will only sign your input files in 'source'.\n")
		return 0
	}

	// Notarize
	color.New(color.Bold).Fprintf(os.Stdout, "==> %s  Notarizing...\n", iconNotarize)
	if len(items) > 1 {
		color.New().Fprintf(os.Stdout, "    Files will be notarized concurrently to optimize queue wait\n")
	}
	for _, f := range items {
		color.New().Fprintf(os.Stdout, "    Path: %s\n", f.Path)
	}

	// Build our prefixes
	prefixes := statusPrefixList(items)

	// Start our notarizations
	var wg sync.WaitGroup
	var lock, uploadLock sync.Mutex
	var totalErr error
	for idx := range items {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			err := items[idx].notarize(context.Background(), &processOptions{
				Config:          cfg,
				Logger:          logger,
				Prefix:          prefixes[idx],
				OutputLock:      &lock,
				UploadLock:      &uploadLock,
				PollingInterval: pollInterval,
			})

			if err != nil {
				lock.Lock()
				defer lock.Unlock()
				totalErr = multierror.Append(totalErr, err)
			}
		}(idx)
	}

	// Wait for notarization to happen
	wg.Wait()

	// If totalErr is not nil then we had one or more errors.
	if totalErr != nil {
		fmt.Fprintf(os.Stdout, color.RedString("\n❗️ Error notarizing:\n\n%s\n", totalErr))
		return 1
	}

	// Success, output all the files that were notarized again to remind the user
	color.New(color.Bold, color.FgGreen).Fprintf(os.Stdout, "\nNotarization complete! Notarized files:\n")
	for _, f := range items {
		color.New(color.FgGreen).Fprintf(os.Stdout, "  - %s\n", f.String())
	}

	return 0
}

func validateAndSetEnv(appleIdCfg *config.AppleId) (status int) {
	const defaultPasswordEnv = "@env:AC_PASSWORD"

	// Set ENV values for unspecified
	if appleIdCfg.Username == "" {
		appleIdCfg.Username = os.Getenv("AC_USERNAME")
	}
	if appleIdCfg.Password == "" {
		appleIdCfg.Password = defaultPasswordEnv
	}
	if appleIdCfg.ApiKey == "" {
		appleIdCfg.ApiKey = os.Getenv("AC_APIKEY")
	}
	if appleIdCfg.ApiIssuer == "" {
		appleIdCfg.ApiIssuer = os.Getenv("AC_APIISSUER")
	}
	if appleIdCfg.Provider == "" {
		appleIdCfg.Provider = os.Getenv("AC_PROVIDER")
	}

	// Nor of authentications methods were chosen.
	if appleIdCfg.Username == "" && appleIdCfg.ApiKey == "" {
		printAppleIdUsage()
		return 1
	}

	// Looks like a password authentication: verify that password is set.
	if appleIdCfg.Username != "" {
		var passwordUnset bool
		envName := strings.TrimPrefix(defaultPasswordEnv, "@env:")
		switch appleIdCfg.Password {
		case "":
			passwordUnset = true
		case defaultPasswordEnv:
			_, passwordUnset = os.LookupEnv(envName)
		}
		if passwordUnset {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout, "❗️ No apple_id `password` provided\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"An Apple ID password (or lookup directive) must be specified in the\n"+
					"`apple_id` block or it must exist in the environment as %s,\n"+
					"otherwise we won't be able to authenticate with Apple to notarize.\n", envName)
			return 1
		}

		// We've got username+password set -- OK now.
		return 0
	}

	// API authentication.
	if appleIdCfg.ApiKey != "" {
		if appleIdCfg.ApiIssuer != "" {
			return 0 // Both API Key and Issuer set -- OK.
		}
		color.New(color.Bold, color.FgRed).Fprintf(os.Stdout, "❗️ No apple_id `api_issuer` provided\n")
		color.New(color.FgRed).Fprintf(os.Stdout,
			"An issuer of the App Store Connect API key must be specified in the\n"+
				"`apple_id` block or it must exist in the environment as AC_APIISSUER,\n"+
				"otherwise we won't be able to authenticate with AC API to notarize.\n")
		return 1
	}

	// Check once more to be sure we didn't missed something.
	switch {
	case appleIdCfg.Username != "" && appleIdCfg.Password != "":
		return 0 // ok
	case appleIdCfg.ApiKey != "" && appleIdCfg.ApiIssuer != "":
		return 0 // ok
	}

	printAppleIdUsage()
	return 1
}

func printAppleIdUsage() {
	color.New(color.Bold, color.FgRed).Fprintf(os.Stdout, "❗️ No apple_id `username` or `api_key` provided\n")
	color.New(color.FgRed).Fprintf(os.Stdout,
		"An Apple ID username OR API key must be specified in the `apple_id` block or\n"+
			"in the appropriate environment variables (AC_USERNAME and AC_APIKEY relatively),\n"+
			"otherwise we won't be able to authenticate with Apple to notarize.\n")
}

func printHelp(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stdout, strings.TrimSpace(help)+"\n\n", os.Args[0])
	fs.PrintDefaults()
}

func parseVersion() (string, error) {
	me, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("can't find myself: %w", err)
	}
	info, err := buildinfo.ReadFile(me)
	if err != nil {
		return "", fmt.Errorf("no buildinfo: %w", err)
	}
	version := info.Main.Version
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			version += " commit " + s.Value
		}
	}
	return version, nil
}

const help = `
gon signs, notarizes, and packages binaries for macOS.

Usage: %[1]s [flags] CONFIG

A configuration file is required to use gon. If a "-" is specified, gon
will attempt to read the configuration from stdin. Configuration is in HCL
or JSON format. The JSON format makes it particularly easy to machine-generate
the configuration and pass it into gon.

For example configurations as well as full help text, see the README on GitHub:
https://github.com/bi-zone/gon

Flags:
`

const iconSign = `✏️`
const iconPackage = `📦`
const iconNotarize = `🍎`
