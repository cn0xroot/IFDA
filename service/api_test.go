package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readFilePreview backs the Files tab's content-preview endpoint. Confirms
// it caps output at filePreviewCap with a truncated flag, and refuses to
// open anything that isn't a regular file -- the same "never open a device
// node/FIFO/socket" rule the Python core's tree-walkers follow, since
// opening one blocks forever rather than erroring.
func TestReadFilePreview(t *testing.T) {
	dir := t.TempDir()

	small := filepath.Join(dir, "small.sh")
	if err := os.WriteFile(small, []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	content, truncated, err := readFilePreview(small)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("small file must not be reported as truncated")
	}
	if content != "#!/bin/sh\necho hi\n" {
		t.Errorf("content = %q", content)
	}

	big := filepath.Join(dir, "big.conf")
	if err := os.WriteFile(big, []byte(strings.Repeat("x", filePreviewCap+100)), 0o644); err != nil {
		t.Fatal(err)
	}
	content, truncated, err = readFilePreview(big)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Error("file over the cap must be reported as truncated")
	}
	if len(content) != filePreviewCap {
		t.Errorf("content length = %d, want %d", len(content), filePreviewCap)
	}

	// A directory is not a regular file -- must error, not hang or panic.
	if _, _, err := readFilePreview(dir); err == nil {
		t.Error("expected an error reading a directory as a file preview")
	}
}
