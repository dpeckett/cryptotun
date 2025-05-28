package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"

	"github.com/urfave/cli/v2"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	CRYPTOTUN_ATTR_LOCAL_PORT  = 1
	CRYPTOTUN_ATTR_REMOTE_PORT = 2
	CRYPTOTUN_ATTR_REMOTE_IP   = 3
	CRYPTOTUN_ATTR_TX_KEY      = 4
	CRYPTOTUN_ATTR_RX_KEY      = 5
)

func uint16ToBytes(val uint16) []byte {
	buf := make([]byte, 2)
	binary.NativeEndian.PutUint16(buf, val)
	return buf
}

func hexStringToBytes(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func addLink(name string, localPort, remotePort uint16, remoteIP string, txKey, rxKey []byte) error {
	linkInfo := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(nl.IFLA_INFO_KIND, nl.NonZeroTerminated("cryptotun"))
	inner := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)

	inner.AddRtAttr(CRYPTOTUN_ATTR_LOCAL_PORT, uint16ToBytes(localPort))
	inner.AddRtAttr(CRYPTOTUN_ATTR_REMOTE_PORT, uint16ToBytes(remotePort))

	remoteAddr, err := netip.ParseAddr(remoteIP)
	if err != nil {
		return fmt.Errorf("invalid remote IP address: %w", err)
	}

	inner.AddRtAttr(CRYPTOTUN_ATTR_REMOTE_IP, nl.ZeroTerminated(remoteAddr.Unmap().String()))
	inner.AddRtAttr(CRYPTOTUN_ATTR_TX_KEY, txKey)
	inner.AddRtAttr(CRYPTOTUN_ATTR_RX_KEY, rxKey)

	flags := unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK
	req := nl.NewNetlinkRequest(unix.RTM_NEWLINK, flags)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(name)))
	req.AddData(linkInfo)

	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		return fmt.Errorf("netlink error: %w", err)
	}

	fmt.Printf("Successfully created cryptotun device: %s\n", name)
	return nil
}

func deleteLink(name string) error {
	req := nl.NewNetlinkRequest(unix.RTM_DELLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(name)))

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		return fmt.Errorf("netlink error: %w", err)
	}

	fmt.Printf("Successfully deleted cryptotun device: %s\n", name)
	return nil
}

func main() {
	app := &cli.App{
		Name:  "cryptotuncli",
		Usage: "Create and manage cryptotun devices",
		Commands: []*cli.Command{
			{
				Name:  "link",
				Usage: "Device management",
				Subcommands: []*cli.Command{
					{
						Name:  "add",
						Usage: "Add a cryptotun link",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "name",
								Required: true,
								Usage:    "Interface name (e.g., vpn0)",
							},
							&cli.UintFlag{
								Name:     "local-port",
								Required: true,
								Usage:    "Local UDP port",
							},
							&cli.UintFlag{
								Name:     "remote-port",
								Required: true,
								Usage:    "Remote UDP port",
							},
							&cli.StringFlag{
								Name:     "remote-ip",
								Required: true,
								Usage:    "Remote IP address (IPv4 or IPv6)",
							},
							&cli.StringFlag{
								Name:     "tx-key",
								Usage:    "Transmit key (16-byte hex string, e.g., deadbeef...0011)",
								Required: true,
							},
							&cli.StringFlag{
								Name:     "rx-key",
								Usage:    "Receive key (16-byte hex string, e.g., deadbeef...0011)",
								Required: true,
							},
						},
						Action: func(c *cli.Context) error {
							var txKey, rxKey []byte
							if txKeyStr := c.String("tx-key"); txKeyStr != "" {
								var err error
								txKey, err = hexStringToBytes(txKeyStr)
								if err != nil {
									return fmt.Errorf("invalid transmit key: %w", err)
								}
								if len(txKey) != 16 {
									return fmt.Errorf("transmit key must be exactly 16 bytes (32 hex characters)")
								}
							}

							if rxKeyStr := c.String("rx-key"); rxKeyStr != "" {
								var err error
								rxKey, err = hexStringToBytes(rxKeyStr)
								if err != nil {
									return fmt.Errorf("invalid receive key: %w", err)
								}
								if len(rxKey) != 16 {
									return fmt.Errorf("receive key must be exactly 16 bytes (32 hex characters)")
								}
							}

							if bytes.Equal(txKey, rxKey) {
								return fmt.Errorf("transmit and receive keys must be different")
							}

							return addLink(
								c.String("name"),
								uint16(c.Uint("local-port")),
								uint16(c.Uint("remote-port")),
								c.String("remote-ip"),
								txKey,
								rxKey,
							)
						},
					},
					{
						Name:  "delete",
						Usage: "Delete a cryptotun link",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "name",
								Required: true,
								Usage:    "Interface name to delete (e.g., vpn0)",
							},
						},
						Action: func(c *cli.Context) error {
							return deleteLink(c.String("name"))
						},
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
