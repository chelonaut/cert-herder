package discovery

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/pkg/errors"
)

func getSSHCertificateChain(ctx context.Context, c Connection, options *Options) (CertificateChain, error) {
	result := make(CertificateChain, 0)

	certChecker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
			// We're choosing to trust whatever certificate the server sends us. We just want to
			// get far enough to see the certificate. In a live scenario we'd be much more careful
			// about which certificates we trust, but this tool is just trying to discover as many
			// certificates as it can so we don't need to be picky here.
			Debug.Printf("IsHostAuthority called with %v", auth)
			cert, ok := auth.(*ssh.Certificate)
			if ok {
				Debug.Printf("IsHostAuthority cert %+v", *cert)
				result = CertificateChain{parseSSHCert(cert)}
			}
			return true
		},

		HostKeyFallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// Again, we're not doing any validation here so let's not return an error.
			Debug.Printf("HostKeyFallback called with %v", key)
			cert, ok := key.(*ssh.Certificate)
			if ok {
				Debug.Printf("Got cert %+v", *cert)
				result = CertificateChain{parseSSHCert(cert)}
			}
			return nil
		},

		IsRevoked: func(cert *ssh.Certificate) bool {
			// If the server has a certificate, we will be given it here
			Debug.Printf("IsRevoked called with %v", cert)
			result = CertificateChain{parseSSHCert(cert)}

			return false
		},
	}

	// Build an SSH configuration.
	config := options.ConfigSSH

	if config == nil {
		// Make a new config
		config = &ssh.ClientConfig{}
	}

	// We need to override this callback so that we can intercept any certificates
	config.HostKeyCallback = certChecker.CheckHostKey

	// Next, build a Dialer so we can connect a socket with a timeout
	addr := net.JoinHostPort(c.IP.String(), strconv.Itoa(int(c.Port)))

	dialer := &net.Dialer{}
	socket, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, errors.Errorf("discovery: getSSHCertificateChain failed to connect: %v", err)
	}
	defer socket.Close()

	// Now negotiate a client connection over the socket
	conn, _, _, err := ssh.NewClientConn(socket, addr, config)
	if err != nil {
		return nil, errors.Wrapf(err, "discovery: getSSHCertificateChain failed to handshake: %v", err)
	}
	defer conn.Close()

	return result, nil
}

func parseSSHCert(cert *ssh.Certificate) *Certificate {
	description := fmt.Sprintf("%v certificate serial %v", cert.Key.Type(), cert.Serial)
	if cert.KeyId != "" {
		description += fmt.Sprintf(" Key ID %v", cert.KeyId)
	}
	if len(cert.ValidPrincipals) > 0 {
		description += fmt.Sprintf(" Valid Principals %v", strings.Join(cert.ValidPrincipals, ","))
	}

	return &Certificate{
		KeyType:       cert.Key.Type(),
		SignatureType: cert.Signature.Format,
		Protocol:      ProtocolSSH,
		Description:   description,
		StartDate:     time.Unix(int64(cert.ValidAfter), 0).UTC(),
		ExpiryDate:    time.Unix(int64(cert.ValidBefore), 0).UTC(),
		Raw:           cert.Marshal(),
	}
}
