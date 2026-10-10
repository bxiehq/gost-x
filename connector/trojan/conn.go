package trojan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"sync"
)

func encodeAddress(address string) ([]byte, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("trojan: invalid port: %w", err)
	}
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append([]byte{1}, v4...)
		} else {
			b = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("trojan: invalid hostname length")
		}
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(p)), nil
}

func readAddress(r io.Reader) (net.Addr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return nil, err
	}
	addressType := atyp[0]
	var length int
	switch addressType {
	case 1:
		length = net.IPv4len
	case 4:
		length = net.IPv6len
	case 3:
		if _, err := io.ReadFull(r, atyp[:]); err != nil {
			return nil, err
		}
		length = int(atyp[0])
		if length == 0 {
			return nil, errors.New("trojan: empty hostname")
		}
	default:
		return nil, errors.New("trojan: invalid address type")
	}
	b := make([]byte, length+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(b[length:]))
	if addressType == 1 || addressType == 4 {
		return &net.UDPAddr{IP: net.IP(b[:length]), Port: port}, nil
	}
	return packetAddr(net.JoinHostPort(string(b[:length]), strconv.Itoa(port))), nil
}

// packetAddr preserves remote DNS resolution for domain-name destinations.
type packetAddr string

func (a packetAddr) Network() string { return "udp" }
func (a packetAddr) String() string  { return string(a) }

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

type udpConn struct {
	net.Conn
	target net.Addr
	rmu    sync.Mutex
	wmu    sync.Mutex
}

var _ net.PacketConn = (*udpConn)(nil)

func (c *udpConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *udpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	addr, err := readAddress(c.Conn)
	if err != nil {
		return 0, nil, err
	}
	var header [4]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, nil, err
	}
	if header[2] != '\r' || header[3] != '\n' {
		return 0, nil, errors.New("trojan: invalid UDP delimiter")
	}
	length := int(binary.BigEndian.Uint16(header[:2]))
	n := min(len(b), length)
	if _, err := io.ReadFull(c.Conn, b[:n]); err != nil {
		return 0, nil, err
	}
	// Consume the entire datagram even if the caller's buffer is too small.
	if _, err := io.CopyN(io.Discard, c.Conn, int64(length-n)); err != nil {
		return n, addr, err
	}
	return n, addr, nil
}

func (c *udpConn) Write(b []byte) (int, error) { return c.WriteTo(b, c.target) }

func (c *udpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) > math.MaxUint16 {
		return 0, errors.New("trojan: UDP payload exceeds 65535 bytes")
	}
	if addr == nil {
		return 0, errors.New("trojan: missing UDP destination")
	}
	frame, err := encodeAddress(addr.String())
	if err != nil {
		return 0, err
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(b)))
	frame = append(frame, '\r', '\n')
	frame = append(frame, b...)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := writeFull(c.Conn, frame); err != nil {
		return 0, err
	}
	return len(b), nil
}
