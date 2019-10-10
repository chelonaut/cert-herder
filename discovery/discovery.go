package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/pkg/errors"
)

var (
	// Debug enables debugging by directing this logger somewhere else
	Debug = log.New(ioutil.Discard, "", log.LstdFlags)

	// Example:
	//Debug = log.New(os.Stderr, "DEBUG: ", log.LstdFlags)
)

// CertificateChain is a chain of certificates obtained from a specific connection,
// with the end-entity certificate first.
type CertificateChain []*Certificate

// Certificate is an abstraction of some of the fields common to X.509 and SSH certificates.
type Certificate struct {
	// Protocol is either "ssh" or "tls" (one of the ProtocolXXXX strings)
	Protocol string

	// Description is a human-readable description of the certificate useful for display purposes
	Description string

	// KeyType is the encryption algorithm used for the public key
	KeyType string

	// SignatureType is the encryption algorithm used to sign the certificate
	SignatureType string

	// StartDate is the UTC date/time when the certificate can first be used
	StartDate time.Time

	// ExpiryDate is the UTC date/time when the certificate expires
	ExpiryDate time.Time

	// Raw is the raw certificate data (exact format depends on the protocol)
	Raw []byte
}

// Options specifies where and how to find certificates.
type Options struct {
	// Places is a list of strings specifying where to handshake with to
	// find certificates. Each place can be one of the following:
	// - An IP address, e.g. "172.16.1.2" (in which case the TCP port 443 is assumed)
	// - An IP address and port number, e.g. "172.16.1.2:8443"
	// - A URL with a scheme such as "https://" or "ssh://" and an IP host, e.g. "https://172.16.1.2" or "ssh://172.16.1.2"
	//
	// Note that a URL with a DNS name is not currently supported, but will be added
	// later.
	//
	// In future versions it is planned to support additional discovery mechanisms
	// such as Kubernetes service discovery using URL schemes and local filesystem
	// discovery.
	Places []string

	// ConfigSSH allows SSH client options to be supplied for any SSH places.
	ConfigSSH *ssh.ClientConfig

	// ConfigTLS allows TLS client options to be supplied for any TLS places.
	ConfigTLS *tls.Config

	// MaximumParallelConnections specifies the maximum number of connections which
	// will be attempted in parallel.
	MaximumParallelConnections int

	// Timeout specifies the maximum time to wait for a single connection attempt.
	// Useful for high network latency or unresponsive remote servers.
	Timeout time.Duration

	// DiscoveredChainFuncs is a slice of callback functions, each of which will be
	// called for each certificate chain found.
	DiscoveredChainFuncs []DiscoveredChainFunc
}

const (
	urlIndicator = "://"

	ProtocolTLS = "tls"
	ProtocolSSH = "ssh"
	// When adding new protocols, remember to update the defaultPortStringToProtocol, protocolToDefaultPort and schemeToProtocol maps.
)

var (
	schemeToProtocol = map[string]string{
		"ssh":   ProtocolSSH,
		"https": ProtocolTLS,
	}

	protocolToDefaultPort = map[string]uint16{
		ProtocolSSH: 22,
		ProtocolTLS: 443,
	}

	defaultPortStringToProtocol = map[string]string{
		"22":  ProtocolSSH,
		"443": ProtocolTLS,
	}
)

// Clone makes a copy of an Options structure
func (o *Options) Clone() *Options {
	// Start with a simple copy of all fields
	result := &Options{}
	*result = *o

	// TLS options need specially cloning, if present
	if o.ConfigTLS != nil {
		result.ConfigTLS = o.ConfigTLS.Clone()
	}

	return result
}

// GetConnections converts the list of Places into specific IP, port and protocol information.
func (o Options) GetConnections() ([]*Connection, error) {
	result := make([]*Connection, 0)

	for index, place := range o.Places {
		connections, err := placeToConnections(place)
		if err != nil {
			return nil, errors.Wrapf(err, "place index %v is invalid", index)
		}

		result = append(result, connections...)
	}

	return result, nil
}

// Validate checks that the Options are understood.
func (o Options) Validate() error {
	if len(o.Places) == 0 {
		return errors.New("no places specified")
	}

	if o.MaximumParallelConnections < 0 {
		return errors.New("MaximumParallelConnections cannot be negative")
	}

	if o.Timeout < 0 {
		return errors.New("Timeout cannot be negative")
	}

	if _, err := o.GetConnections(); err != nil {
		return err
	}

	// If we get here, everything is good
	return nil
}

// Connection represents a connection that needs to be made to a specific IP address,
// port number and protocol combination to check for a certificate. It's really the
// specification for a connection which will be made.
type Connection struct {
	IP   net.IP
	Port uint16

	// Protocol is one of the ProtocolXXXX strings, e.g. "ssh" or "tls". It indicates
	// how the connection will be made when checking for certificates.
	Protocol string

	// Host contains the original string which we resolved into IPs. It's useful for
	// TLS connections as we can set Server Name Indication in the ClientHello so that
	// multi-hosting TLS servers can present us with the correct certificate.
	Host string
}

// GetCertificateChain opens a connection to the IP address and port specified in the
// Connection and attempts a handshake using the Connection Protocol. It then returns
// the certificate chain it obtained, if any.
func (c Connection) GetCertificateChain(ctx context.Context, options *Options) (CertificateChain, error) {
	// Make a copy so that we can modify without affecting the caller
	options = options.Clone()

	switch c.Protocol {
	case ProtocolSSH:
		return getSSHCertificateChain(ctx, c, options)
	case ProtocolTLS:
		return getTLSCertificateChain(ctx, c, options)
	default:
		return nil, errors.Errorf("discovery: protocol discovery for '%v' not implemented.", c.Protocol)
	}
}

// String returns a string representation of the connection.
func (c Connection) String() string {
	result := c.Protocol + " "
	if c.Host != "" && c.Host != c.IP.String() {
		result += fmt.Sprintf("%v:%v (%v:%v)", c.Host, c.Port, c.IP.String(), c.Port)
	} else {
		result += fmt.Sprintf("%v:%v", c.IP.String(), c.Port)
	}
	return result
}

// Given a URL host name, convert it to a slice of IP addresses.
func hostToIPs(h string) ([]net.IP, error) {
	// Is this a single IP address?
	ip := net.ParseIP(h)
	if ip != nil {
		// This was a single IP address, so return it
		return []net.IP{ip}, nil
	}

	// Is this a CIDR block?
	if strings.Contains(h, "/") {
		ip, lastIP, err := getFirstAndLastIPs(h)
		if err != nil {
			return nil, errors.Errorf("discovery: error resolving CIDR block '%v': %v", h, err)
		}

		// The very first IP is a base subnet address so increment it as we
		// don't want to use it.
		incrementIP(ip)

		// The very last IP is a broadcast address so decrement it as we don't
		// want to use it.
		lastIP[len(lastIP)-1]--

		// Generate the list of all IPs in this CIDR block, one at a time by
		// incrementing the start IP until we reach the last IP in the block.
		// To safeguard against absurdly large IP ranges we have a limit.
		result := []net.IP{}

		for {
			result = append(result, copyIP(ip))

			if ip.Equal(lastIP) {
				break
			}

			incrementIP(ip)
		}

		return result, nil
	}

	// Resolve via DNS
	result := []net.IP{}
	addrs, err := net.LookupHost(h)
	if err != nil {
		return nil, errors.Errorf("discovery: error resolving host '%v': %v", h, err)
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip != nil {
			result = append(result, ip)
		}
	}

	return result, nil
}

func copyIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)
	return result
}

func getFirstAndLastIPs(cidr string) (net.IP, net.IP, error) {
	firstIP, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "unable to parse CIDR address block '%v': ", cidr)
	}

	lastIP := copyIP(firstIP)

	// Invert the network mask to produce a host mask
	mask := ipnet.Mask

	for i := 0; i < len(mask); i++ {
		mask[i] = ^mask[i]
	}

	// OR the host part onto the IP.
	// Note that for IPv4 the mask is shorter than the IP so we need to track
	// positions separately.
	ipIndex := len(lastIP) - 1
	maskIndex := len(mask) - 1
	for ipIndex >= 0 && maskIndex >= 0 {
		lastIP[ipIndex] |= mask[maskIndex]

		maskIndex--
		ipIndex--
	}

	return firstIP, lastIP, nil
}

func incrementIP(ip net.IP) {
	// Increment starts at the right-hand side of the IP
	index := len(ip) - 1

	// Count how many bytes remain to be processed. Note that golang usually represents
	// IPv4 embedded inside a 16-byte IPv6 IP so we need to keep track of when we have
	// no more bytes we can increment.
	bytesRemaining := len(ip)
	if ip.To4() != nil {
		bytesRemaining = 4
	}

	for {
		ip[index]++
		bytesRemaining--

		if ip[index] != 0 {
			// We didn't wrap this byte back to zero so increment is complete
			break
		}

		if bytesRemaining < 1 {
			// We wrapped, but there are no more bytes so we're done.
			break
		}

		// Move to the next byte
		index--
	}
}

// Given a single place string from the Options structure, parse it into a Connection
// structure indicating where and how to connect. This function is coded to return
// a slice of Connections because DNS lookups of host names or future service discovery
// could return multiple Connections to check.
func placeToConnections(p string) ([]*Connection, error) {
	if strings.Contains(p, urlIndicator) {
		return urlToConnections(p)
	}

	var err error
	var host string
	var ips []net.IP
	var port uint16
	var portstr string
	var protocol string

	if strings.Contains(p, ":") {
		host, portstr, err = net.SplitHostPort(p)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to determine host and port in '%v'", p)
		}

		ips, err = hostToIPs(host)
		if err != nil {
			return nil, err
		}

		protocol = defaultPortStringToProtocol[portstr]
		if protocol == "" {
			protocol = ProtocolTLS
		}

		port = parsePort(protocol, portstr)

	} else {
		host = p

		ips, err = hostToIPs(p)
		if err != nil {
			return nil, err
		}

		protocol = ProtocolTLS
		port = 443
	}

	// Generate a result for each permutation of IP/port/protocol
	result := make([]*Connection, 0)

	for _, ip := range ips {
		connection := &Connection{
			Host:     host,
			IP:       ip,
			Port:     port,
			Protocol: protocol,
		}
		result = append(result, connection)
	}

	return result, nil
}

// Given a port string, convert it to a number. If the string is not a valid port
// number then return a default port number for the given protocol. If the protocol
// is not a known string and the port is invalid then 443 is returned.
func parsePort(protocol, port string) uint16 {
	result, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		result := protocolToDefaultPort[protocol]
		if result == 0 {
			result = 443
		}
		return result
	}

	return uint16(result)
}

// Convert a URL to a slice of Connections
func urlToConnections(p string) ([]*Connection, error) {
	u, err := url.Parse(p)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid URL '%v'", p)
	}

	// Check we can map the scheme to a known protocol
	protocol := schemeToProtocol[u.Scheme]
	if protocol == "" {
		return nil, errors.Errorf("URL scheme '%v' does not map to a known protocol", u.Scheme)
	}

	// Convert the host name to a slice of IPs
	ips, err := hostToIPs(u.Hostname())
	if err != nil {
		return nil, err
	}

	port := parsePort(protocol, u.Port())

	// Generate a result for each permutation of IP/port/protocol
	result := make([]*Connection, 0)

	for _, ip := range ips {
		connection := &Connection{
			Host:     u.Hostname(),
			IP:       ip,
			Port:     port,
			Protocol: protocol,
		}
		result = append(result, connection)
	}

	return result, nil
}
