// internal/vm/vm.go

package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/anatol/vmtest"
	"github.com/avast/retry-go/v4"
	"github.com/bramvdbogaerde/go-scp"
	"golang.org/x/crypto/ssh"
)

type VMOption func(*options)

type socketNicOptions struct {
	listen  bool
	address string
}

type options struct {
	imagePath    string
	isoPath      string
	socketNIC    *socketNicOptions
	snapshotMode bool
}

func WithImagePath(imagePath string) VMOption {
	return func(opts *options) {
		opts.imagePath = imagePath
	}
}

func WithISOPath(isoPath string) VMOption {
	return func(opts *options) {
		opts.isoPath = isoPath
	}
}

func WithSocketNIC(listen bool, address string) VMOption {
	return func(opts *options) {
		opts.socketNIC = &socketNicOptions{
			listen:  listen,
			address: address,
		}
	}
}

func WithSnapshotMode(snapshot bool) VMOption {
	return func(opts *options) {
		opts.snapshotMode = snapshot
	}
}

type VMInstance struct {
	vm        *vmtest.Qemu
	sshPort   int
	sshClient *ssh.Client
}

func NewVMInstance(opts ...VMOption) (*VMInstance, error) {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	sshPort, err := getFreePort()
	if err != nil {
		return nil, fmt.Errorf("failed to find free port: %w", err)
	}

	params := []string{
		"-cpu", "host",
		"-smp", fmt.Sprintf("%d", runtime.NumCPU()),
		"-m", "1G",
		"-enable-kvm",
		"-netdev", fmt.Sprintf("user,id=net0,hostfwd=tcp::%d-:22", sshPort),
		"-device", "virtio-net,netdev=net0,mac=f6:69:d0:94:6d:0f",
	}

	if options.socketNIC != nil {
		if options.socketNIC.listen {
			params = append(params, "-netdev", fmt.Sprintf("socket,id=net1,listen=%s", options.socketNIC.address))
		} else {
			params = append(params, "-netdev", fmt.Sprintf("socket,id=net1,connect=%s", options.socketNIC.address))
		}
		params = append(params, "-device", "virtio-net,netdev=net1,mac=e2:65:4d:6e:22:33")
	}

	if options.snapshotMode {
		params = append(params, "-snapshot")
	}

	qemuOpts := vmtest.QemuOptions{
		Architecture:    vmtest.QEMU_X86_64,
		OperatingSystem: vmtest.OS_LINUX,
		Disks:           []vmtest.QemuDisk{{Path: options.imagePath, Format: "qcow2"}},
		CdRom:           options.isoPath,
		Params:          params,
		Verbose:         true,
		Timeout:         300 * time.Second,
	}

	vm, err := vmtest.NewQemu(&qemuOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM: %w", err)
	}

	return &VMInstance{
		vm:      vm,
		sshPort: sshPort,
	}, nil
}

func (vm *VMInstance) Connect(ctx context.Context) error {
	sshCfg := &ssh.ClientConfig{
		User:            "vmtest",
		Auth:            []ssh.AuthMethod{ssh.Password("vmtest")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         1 * time.Second,
	}

	var client *ssh.Client
	err := retry.Do(
		func() error {
			var connErr error
			client, connErr = dialSSHContext(ctx, net.JoinHostPort("localhost", fmt.Sprintf("%d", vm.sshPort)), sshCfg)
			if connErr != nil {
				slog.Warn("SSH connection failed", slog.Any("error", connErr))
			}
			return connErr
		},
		retry.Attempts(10),
		retry.Delay(3*time.Second),
		retry.Context(ctx),
	)
	if err != nil {
		return fmt.Errorf("SSH connection failed: %w", err)
	}

	vm.sshClient = client
	return nil
}

func (vm *VMInstance) CopyFile(ctx context.Context, localPath, remotePath string, perm os.FileMode) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file %s: %w", localPath, err)
	}
	defer f.Close()

	scpClient, err := scp.NewClientBySSH(vm.sshClient)
	if err != nil {
		return fmt.Errorf("failed to create SCP client: %w", err)
	}
	defer scpClient.Close()

	permStr := fmt.Sprintf("%04o", perm&os.ModePerm)
	if err := scpClient.CopyFile(ctx, f, remotePath, permStr); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("failed to copy file to VM: %w", err)
	}

	return nil
}

func (vm *VMInstance) RunCommand(ctx context.Context, cmd string) error {
	session, err := vm.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return fmt.Errorf("command canceled: %w", ctx.Err())
	case err := <-done:
		if err != nil {
			return fmt.Errorf("command failed: %w", err)
		}
		return nil
	}
}

func (vm *VMInstance) Shutdown() {
	if vm.sshClient != nil {
		vm.sshClient.Close()
		vm.sshClient = nil
	}
	if vm.vm != nil {
		vm.vm.Shutdown()
		vm.vm = nil
	}
}

func getFreePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func dialSSHContext(ctx context.Context, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}
