package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"

	"github.com/pkg/errors"
)

func getTLSCertificateChain(ctx context.Context, c Connection, options *Options) (CertificateChain, error) {
	// First, build a TLS configuration.
	config := options.ConfigTLS

	if config == nil {
		// Make a new config
		config = &tls.Config{}
	}

	// Specify server hostname to help the server send the right certificate
	config.ServerName = c.Host

	// Don't be too strict when checking certificates, we're just trying to maximise the number of successful
	// handshakes so that we can gather as many certificates as possible. Using this setting is bad practice
	// in live production code, but if anyone has disabled certificate validation in their application code
	// they may well be using certificates which don't conform to the proper standards so we want to gather
	// such certificates.
	config.InsecureSkipVerify = true

	// Next, build a Dialer so we can connect a socket with a timeout
	dialer := &net.Dialer{}
	socket, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(c.IP.String(), strconv.Itoa(int(c.Port))))
	if err != nil {
		return nil, errors.Errorf("discovery: GetTLSCertificateChain failed to connect: %v", err)
	}
	defer socket.Close()

	// Now negotiate a client connection over the socket
	conn := tls.Client(socket, config)
	defer conn.Close()

	err = conn.Handshake()
	if err != nil {
		return nil, errors.Errorf("discovery: GetTLSCertificateChain failed to handshake: %v", err)
	}

	// Get the certificate chain details
	connState := conn.ConnectionState()

	return parseX509Chain(connState.PeerCertificates), nil
}

func parseX509Chain(peerX509Certs []*x509.Certificate) CertificateChain {
	result := make(CertificateChain, 0)

	for _, peerX509Cert := range peerX509Certs {
		result = append(result, parseX509Cert(peerX509Cert))
	}

	return result
}

func parseX509Cert(cert *x509.Certificate) *Certificate {
	return &Certificate{
		KeyType:       cert.PublicKeyAlgorithm.String(),
		Protocol:      ProtocolTLS,
		SignatureType: cert.SignatureAlgorithm.String(),
		Description: fmt.Sprintf("%v certificate for %v (start %v, expires: %v)",
			cert.PublicKeyAlgorithm.String(),
			cert.Subject.String(),
			cert.NotBefore.UTC().String(),
			cert.NotAfter.UTC().String(),
		),
		StartDate:  cert.NotBefore.UTC(),
		ExpiryDate: cert.NotAfter.UTC(),
		Raw:        cert.Raw,
	}
}
