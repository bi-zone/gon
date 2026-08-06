package zip

import (
	archivezip "archive/zip"
	"context"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestZip_keepsDirectoryEntry verifies that zipping a directory source (such
// as an .app bundle) keeps the directory itself as a top-level entry in the
// archive instead of flattening its contents into the archive root, which
// breaks notarization.
func TestZip_keepsDirectoryEntry(t *testing.T) {
	if _, err := exec.LookPath("ditto"); err != nil {
		t.Skip("ditto not available")
	}

	dir, err := ioutil.TempDir("", "gon-zip-test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// Build a fake .app bundle and a standalone file as sources
	appDir := filepath.Join(dir, "Test.app")
	require.NoError(t, os.MkdirAll(filepath.Join(appDir, "Contents"), 0755))
	require.NoError(t, ioutil.WriteFile(
		filepath.Join(appDir, "Contents", "Info.plist"), []byte("plist"), 0644))
	binFile := filepath.Join(dir, "test-bin")
	require.NoError(t, ioutil.WriteFile(binFile, []byte("bin"), 0755))

	outputPath := filepath.Join(dir, "out.zip")
	require.NoError(t, Zip(context.Background(), &Options{
		Files:      []string{appDir, binFile},
		OutputPath: outputPath,
	}))

	r, err := archivezip.OpenReader(outputPath)
	require.NoError(t, err)
	defer r.Close()

	names := map[string]bool{}
	for _, f := range r.File {
		names[f.Name] = true
	}

	require.True(t, names["Test.app/Contents/Info.plist"],
		"bundle contents must be nested under the bundle directory, got: %v", names)
	require.True(t, names["test-bin"], "plain file must be at the archive root, got: %v", names)
	require.False(t, names["Contents/Info.plist"],
		"bundle contents must not be flattened into the archive root, got: %v", names)
}
