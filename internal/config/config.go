package config

// Config is the configuration structure for gon.
type Config struct {
	// Source is the list of binary files to sign.
	Source []string `hcl:"source,optional"`

	// BundleId is the bundle ID to use for the package that is created.
	// This should be in a format such as "com.example.app". The value can
	// be anything, this is required by Apple.
	BundleId string `hcl:"bundle_id,optional"`

	// Notarize is a single file (usually a .pkg installer or zip)
	// that is ready for notarization as-is
	Notarize []Notarize `hcl:"notarize,block"`

	// Sign are the settings for code-signing the binaries.
	Sign *Sign `hcl:"sign,block"`

	// AppleId are the credentials to use to talk to Apple.
	AppleId *AppleId `hcl:"apple_id,block"`

	// Zip, if present, creates a notarized zip file as the output. Note
	// that zip files do not support stapling, so the final result will
	// require an internet connection on first use to validate the notarization.
	Zip *Zip `hcl:"zip,block"`

	// Dmg, if present, creates a dmg file to package the signed `Source` files
	// into. Dmg files support stapling so this allows offline usage.
	Dmg *Dmg `hcl:"dmg,block"`
}

// AppleId are the authentication settings for Apple systems.
type AppleId struct {
	// Username is your AC username, typically an email. This is required, but will
	// be read from the environment via AC_USERNAME if not specified via config.
	Username string `hcl:"username,optional"`

	// Password is the password for your AC account. This also accepts
	// two additional forms: '@keychain:<name>' which reads the password from
	// the keychain and '@env:<name>' which reads the password from an
	// environmental variable named <name>. If omitted, it has the same effect
	// as passing '@env:AC_PASSWORD'.
	Password string `hcl:"password,optional"`

	// ApiKey is the name (ID) of an API key generated on App Store Connect portal.
	//
	// You must specify either Username and Password or ApiKey and ApiIssuer.
	// API authorization takes precedence over the username+password one.
	//
	// If omitted will be set from environment via AC_APIKEY.
	ApiKey string `hcl:"api_key,optional"`

	// ApiKeyPath specifies an exact path to the API key file in a `.p8` format.
	//
	// If omitted, `gon` will search for an 'AuthKey_<api_key>.p8' file in a one of the
	// following directories './private_keys', '~/private_keys', '~/.private_keys',
	// '~/.appstoreconnect/private_keys' or in dir specified via API_PRIVATE_KEYS_DIR env.
	ApiKeyPath string `hcl:"api_key_path,optional"`

	// ApiIssuer is the ID of the specified ApiKey Issuer. Required if ApiKey is specified.
	//
	// If omitted will be set from environment via AC_APIISSUER.
	ApiIssuer string `hcl:"api_issuer,optional"`

	// Provider is the AC provider. This is optional and only needs to be
	// specified if you're using an Apple ID account that has multiple
	// teams.
	Provider string `hcl:"provider,optional"`
}

// Notarize are the options for notarizing a pre-built file.
type Notarize struct {
	// Path is the path to the file to notarize. This can be any supported
	// filetype (dmg, pkg, app, zip).
	Path string `hcl:"path"`

	// BundleId is the bundle ID to use for notarizing this package.
	// If this isn't specified then the root bundle_id is inherited.
	BundleId string `hcl:"bundle_id"`

	// Staple, if true will staple the notarization ticket to the file.
	Staple bool `hcl:"staple,optional"`
}

// Sign are the options for codesigning the binaries.
type Sign struct {
	// ApplicationIdentity is the ID or name of the certificate to
	// use for signing binaries. This is used for all binaries in "source".
	ApplicationIdentity string `hcl:"application_identity"`

	// Specify a path to an entitlements file in plist format
	EntitlementsFile string `hcl:"entitlements_file,optional"`
}

// Dmg are the options for a dmg file as output.
type Dmg struct {
	// OutputPath is the path where the final dmg will be saved.
	OutputPath string `hcl:"output_path"`

	// Volume name is the name of the volume that shows up in the title
	// and sidebar after opening it.
	VolumeName string `hcl:"volume_name"`

	// SkipPrettification disables running of prettification logic of `create-dmg`.
	// The logic itself is relied on AppleScript and could be faulty on CI or restricted env.
	//
	// N.B. Enabling this option will make opened `.dmg` in finder less pretty than before.
	SkipPrettification bool `hcl:"skip_prettification,optional"`
}

// Zip are the options for a zip file as output.
type Zip struct {
	// OutputPath is the path where the final zip file will be saved.
	OutputPath string `hcl:"output_path"`
}
