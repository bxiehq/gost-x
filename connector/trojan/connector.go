// Package trojan implements the Trojan client protocol over a stream transport.
// Use the TLS dialer for standard Trojan servers.
package trojan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/connector"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("trojan", NewConnector)
}

type trojanConnector struct {
	hash    string
	md      metadata
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	var options connector.Options
	for _, opt := range opts {
		opt(&options)
	}
	return &trojanConnector{options: options}
}

func (c *trojanConnector) Init(md md.Metadata) error {
	c.hash = ""
	if err := c.parseMetadata(md); err != nil {
		return err
	}
	if c.options.Auth == nil {
		return errors.New("trojan: password is required")
	}
	password, hasPassword := c.options.Auth.Password()
	// Trojan share links put the password in the URL username field.
	if !hasPassword {
		password = c.options.Auth.Username()
	}
	if password == "" {
		return errors.New("trojan: password is required")
	}
	hash := sha256.Sum224([]byte(password))
	c.hash = hex.EncodeToString(hash[:])
	return nil
}

func (c *trojanConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.hash == "" {
		return nil, errors.New("trojan: connector is not initialized")
	}
	var command byte
	switch network {
	case "tcp", "tcp4", "tcp6":
		command = 1
	case "udp", "udp4", "udp6":
		command = 3
	default:
		return nil, fmt.Errorf("trojan: network %s is unsupported", network)
	}
	if _, ok := conn.(net.PacketConn); ok {
		return nil, errors.New("trojan: stream transport is required")
	}
	target, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if c.md.connectTimeout > 0 {
		timeout := time.Now().Add(c.md.connectTimeout)
		if deadline.IsZero() || timeout.Before(deadline) {
			deadline = timeout
		}
	}
	if !deadline.IsZero() {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
		defer conn.SetDeadline(time.Time{})
	}
	header := append([]byte(c.hash+"\r\n"), command)
	header = append(header, target...)
	header = append(header, '\r', '\n')
	if err := writeFull(conn, header); err != nil {
		return nil, err
	}
	if command == 3 {
		return &udpConn{Conn: conn, target: packetAddr(address)}, nil
	}
	return conn, nil
}
