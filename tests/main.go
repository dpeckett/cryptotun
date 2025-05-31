package main

import (
	"context"
	"cryptotuntests/internal/cloudinit"
	vm "cryptotuntests/internal/vm"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/mholt/archives"
	ignore "github.com/sabhiram/go-gitignore"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"
)

const (
	imageURL  = "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
	imageName = "debian-12-genericcloud.qcow2"
)

func main() {
	app := &cli.App{
		Name:   "cryptotuntests",
		Usage:  "Run tests for cryptotun",
		Action: runVM,
	}

	if err := app.Run(os.Args); err != nil {
		slog.Error("Application failed", slog.Any("error", err))
		os.Exit(1)
	}
}

func runVM(c *cli.Context) error {
	tempDir, err := os.MkdirTemp("", "cryptotun-tests")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	imageDir, err := xdg.CacheFile("cryptotun-tests")
	if err != nil {
		return fmt.Errorf("failed to get cache directory: %w", err)
	}

	imagePath := filepath.Join(imageDir, imageName)

	if _, err := os.Stat(imagePath); os.IsNotExist(err) {
		slog.Info("Downloading Debian 12 generic cloud image", slog.String("url", imageURL), slog.String("path", imagePath))
		if err := downloadFile(imageURL, imagePath); err != nil {
			return fmt.Errorf("failed to download image: %w", err)
		}

		slog.Info("Provisioning VM with downloaded image", slog.String("path", imagePath))
		if err := provisionVM(c.Context, tempDir, imagePath); err != nil {
			return fmt.Errorf("failed to provision VM: %w", err)
		}
		slog.Info("VM provisioned successfully", slog.String("path", imagePath))
	}

	slog.Info("Creating tarball of cryptotun source code")

	gitDir, err := findGitRoot()
	if err != nil {
		return fmt.Errorf("failed to find git root directory: %w", err)
	}

	slog.Info("Found git root directory", slog.String("path", gitDir))

	tarPath := filepath.Join(tempDir, "cryptotun.tar.gz")
	if err := createTarball(c.Context, gitDir, tarPath); err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(c.Context)

	g.Go(func() error {
		vminst, err := bootTestVM(ctx, imagePath, gitDir, tarPath, true)
		if err != nil {
			return fmt.Errorf("failed to boot test VM: %w", err)
		}
		defer vminst.Shutdown()

		slog.Info("Waiting for peer VM to be reachable")

		if err := vminst.RunCommand(ctx, "until ping -c1 -W1 10.0.0.2 >/dev/null 2>&1; do sleep 1; done"); err != nil {
			return fmt.Errorf("peer vm did not respond to ping: %w", err)
		}

		slog.Info("Initializing cryptotun NIC")

		if err := vminst.RunCommand(ctx, "sudo cryptotuncli link add --name=vpn0 --local-port=1234 --remote-ip=10.0.0.2 --remote-port=1234 --tx-key=0123456789abcdef0123456789abcdef --rx-key=fedcba9876543210fedcba9876543210"); err != nil {
			return fmt.Errorf("failed to initialize cryptotun NIC: %w", err)
		}

		if err := vminst.RunCommand(ctx, "sudo ip addr add 10.0.1.1/24 dev vpn0 && sudo ip link set vpn0 up"); err != nil {
			return fmt.Errorf("failed to set IP address: %w", err)
		}

		if err := vminst.RunCommand(ctx, "iperf3 -s -B 10.0.1.1"); err != nil {
			return fmt.Errorf("failed to start iperf3 server: %w", err)
		}

		return nil
	})

	g.Go(func() error {
		// Staggered boot.
		time.Sleep(5 * time.Second)

		vminst, err := bootTestVM(ctx, imagePath, gitDir, tarPath, false)
		if err != nil {
			return fmt.Errorf("failed to boot test VM: %w", err)
		}
		defer vminst.Shutdown()

		slog.Info("Waiting for peer VM to be reachable")

		if err := vminst.RunCommand(ctx, "until ping -c1 -W1 10.0.0.1 >/dev/null 2>&1; do sleep 1; done"); err != nil {
			return fmt.Errorf("VM did not respond to ping: %w", err)
		}

		slog.Info("Initializing cryptotun NIC")

		if err := vminst.RunCommand(ctx, "sudo cryptotuncli link add --name=vpn0 --local-port=1234 --remote-ip=10.0.0.1 --remote-port=1234 --tx-key=fedcba9876543210fedcba9876543210 --rx-key=0123456789abcdef0123456789abcdef"); err != nil {
			return fmt.Errorf("failed to initialize cryptotun NIC: %w", err)
		}

		if err := vminst.RunCommand(ctx, "sudo ip addr add 10.0.1.2/24 dev vpn0 && sudo ip link set vpn0 up"); err != nil {
			return fmt.Errorf("failed to set IP address: %w", err)
		}

		if err := vminst.RunCommand(ctx, "iperf3 -c 10.0.1.1 -t 10"); err != nil {
			return fmt.Errorf("failed to run iperf3 client: %w", err)
		}

		return context.Canceled // signal completion
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}

func bootTestVM(ctx context.Context, imagePath, gitDir, tarPath string, listen bool) (*vm.VMInstance, error) {
	vminst, err := vm.NewVMInstance(
		vm.WithImagePath(imagePath),
		vm.WithSocketNIC(listen, "localhost:1234"),
		vm.WithSnapshotMode(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM instance: %w", err)
	}

	slog.Info("Waiting for VM to boot")
	if err := vminst.Connect(ctx); err != nil {
		vminst.Shutdown()
		return nil, fmt.Errorf("failed to boot VM: %w", err)
	}

	slog.Info("Copying cryptotun tarball to VM", slog.String("path", tarPath))
	if err := vminst.CopyFile(ctx, tarPath, "/home/vmtest/cryptotun.tar.gz", 0o644); err != nil {
		vminst.Shutdown()
		return nil, fmt.Errorf("failed to copy tarball to VM: %w", err)
	}

	slog.Info("Copying cryptotun cli to VM")
	if err := vminst.CopyFile(ctx, filepath.Join(gitDir, "cli/cryptotuncli"), "/home/vmtest/cryptotuncli", 0o755); err != nil {
		vminst.Shutdown()
		return nil, fmt.Errorf("failed to copy cryptotun CLI to VM: %w", err)
	}

	if err := vminst.RunCommand(ctx, "sudo mv /home/vmtest/cryptotuncli /usr/local/bin/"); err != nil {
		vminst.Shutdown()
		return nil, fmt.Errorf("failed to move cryptotun CLI to /usr/local/bin: %w", err)
	}

	slog.Info("Extracting cryptotun tarball")
	if err := vminst.RunCommand(ctx, "tar -xzf /home/vmtest/cryptotun.tar.gz && rm cryptotun.tar.gz"); err != nil {
		vminst.Shutdown()
		return nil, fmt.Errorf("failed to extract tarball in VM: %w", err)
	}

	slog.Info("Compiling and loading cryptotun module")
	if err := vminst.RunCommand(ctx, "cd cryptotun && make && sudo insmod ./cryptotun.ko && echo 'module cryptotun +p' | sudo tee /sys/kernel/debug/dynamic_debug/control > /dev/null"); err != nil {
		vminst.Shutdown()
		return nil, fmt.Errorf("failed to compile and load cryptotun module: %w", err)
	}

	var address string
	if listen {
		address = "10.0.0.1/24"
	} else {
		address = "10.0.0.2/24"
	}

	slog.Info("Setting up socket interface")
	if err := vminst.RunCommand(ctx, fmt.Sprintf(
		"sudo ip addr add %s dev eth1 && sudo ip link set eth1 up",
		address,
	)); err != nil {
		vminst.Shutdown()
		return nil, fmt.Errorf("failed to set up cryptotun interface: %w", err)
	}

	return vminst, nil
}

func downloadFile(url, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	_, err = io.Copy(f, resp.Body)
	return err
}

func createTarball(ctx context.Context, srcDir, dstPath string) error {
	type ignoreEntry struct {
		dir   string
		rules *ignore.GitIgnore
	}

	var (
		ignoreStack []ignoreEntry
		files       = make(map[string]string)
	)

	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Pop ignore entries for directories we have exited
		for len(ignoreStack) > 0 && !strings.HasPrefix(path, ignoreStack[len(ignoreStack)-1].dir+string(os.PathSeparator)) {
			ignoreStack = ignoreStack[:len(ignoreStack)-1]
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		// If it's a directory, check for a .gitignore file and push it onto the stack if found
		if d.IsDir() {
			gitignorePath := filepath.Join(path, ".gitignore")
			if stat, err := os.Stat(gitignorePath); err == nil && !stat.IsDir() {
				rules, err := ignore.CompileIgnoreFile(gitignorePath)
				if err != nil {
					return fmt.Errorf("failed to parse %s: %w", gitignorePath, err)
				}
				ignoreStack = append(ignoreStack, ignoreEntry{dir: path, rules: rules})
			}
			return nil
		}

		// Check ignore rules from deepest to shallowest
		for i := len(ignoreStack) - 1; i >= 0; i-- {
			entry := ignoreStack[i]
			if strings.HasPrefix(path, entry.dir+string(os.PathSeparator)) {
				relToIgnoreDir, _ := filepath.Rel(entry.dir, path)
				if entry.rules.MatchesPath(relToIgnoreDir) {
					return nil
				}
			}
		}

		files[path] = filepath.Join("cryptotun", relPath)
		return nil
	})

	if err != nil {
		return err
	}

	archive, err := archives.FilesFromDisk(ctx, nil, files)
	if err != nil {
		return err
	}

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	format := archives.CompressedArchive{
		Compression: archives.Gz{},
		Archival:    archives.Tar{},
	}
	return format.Archive(ctx, dst, archive)
}

func provisionVM(ctx context.Context, tempDir, imagePath string) error {
	isoPath := filepath.Join(tempDir, "cloud-init.iso")
	slog.Info("Creating cloud-init ISO", slog.String("path", isoPath))
	if err := cloudinit.CreateISO(isoPath); err != nil {
		return fmt.Errorf("failed to create cloud-init ISO: %w", err)
	}

	vminst, err := vm.NewVMInstance(
		vm.WithImagePath(imagePath),
		vm.WithSocketNIC(true, "localhost:1234"),
		vm.WithISOPath(isoPath),
		vm.WithSnapshotMode(false),
	)
	if err != nil {
		return fmt.Errorf("failed to create VM instance: %w", err)
	}
	defer vminst.Shutdown()

	slog.Info("Waiting for VM to boot")
	if err := vminst.Connect(ctx); err != nil {
		return err
	}

	slog.Info("Waiting for cloud-init to complete")
	if err := vminst.RunCommand(ctx, "cloud-init status --wait"); err != nil {
		return fmt.Errorf("cloud-init did not complete successfully: %w", err)
	}

	slog.Info("VM is ready and cloud-init completed")
	return nil
}

func findGitRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("not inside a git repository")
}
