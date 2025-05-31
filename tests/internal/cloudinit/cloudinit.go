package cloudinit

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"

	"github.com/kdomanski/iso9660"
)

//go:embed metadata.yaml
var metaData string

//go:embed network-config.yaml
var networkConfig string

//go:embed cloud-config.yaml
var userData string

func CreateISO(path string) error {
	w, err := iso9660.NewWriter()
	if err != nil {
		return fmt.Errorf("failed to create iso9660 writer: %w", err)
	}

	if err := w.AddFile(bytes.NewReader([]byte(userData)), "user-data"); err != nil {
		return fmt.Errorf("failed to add user-data to ISO: %w", err)
	}

	if err := w.AddFile(bytes.NewReader([]byte(networkConfig)), "network-config"); err != nil {
		return fmt.Errorf("failed to add network-config to ISO: %w", err)
	}

	if err := w.AddFile(bytes.NewReader([]byte(metaData)), "meta-data"); err != nil {
		return fmt.Errorf("failed to add meta-data to ISO: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create ISO file: %w", err)
	}
	defer f.Close()

	if err := w.WriteTo(f, "cidata"); err != nil {
		return fmt.Errorf("failed to write ISO: %w", err)
	}

	return w.Cleanup()
}
