package discovery

import (
	"context"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"golang.org/x/crypto/ssh"

	"crypto/rand"
	"crypto/rsa"
)

var (
	testOnce sync.Once

	testSSHHostPrivateKey   ssh.Signer
	testSSHHostCertificate  *ssh.Certificate
	testSSHClientPrivateKey ssh.Signer
	testCertStartDate       time.Time
	testCertExpiryDate      time.Time
)

func initTestKeys(t *testing.T) {

	// Generate CA key and a self-signed CA certificate
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caPublicKey, err := ssh.NewPublicKey(&caPrivateKey.PublicKey)
	require.NoError(t, err)

	caSelfSigner, err := ssh.NewSignerFromKey(caPrivateKey)
	require.NoError(t, err)

	caCertificate := &ssh.Certificate{
		Nonce:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, // dummy value only
		Key:          caPublicKey,
		Serial:       1,
		ValidAfter:   0,
		ValidBefore:  math.MaxUint64,
		SignatureKey: caPublicKey,
	}

	err = caCertificate.SignCert(rand.Reader, caSelfSigner)
	require.NoError(t, err)

	caSigner, err := ssh.NewCertSigner(caCertificate, caSelfSigner)
	require.NoError(t, err)

	// Generate server host key and certificate
	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serverPrivateKeySigner, err := ssh.NewSignerFromKey(serverPrivateKey)
	require.NoError(t, err)

	serverPublicKey, err := ssh.NewPublicKey(&serverPrivateKey.PublicKey)
	require.NoError(t, err)

	testCertStartDate, err = time.Parse(time.RFC3339, "2001-06-21T13:23:13Z")
	require.NoError(t, err)

	testCertExpiryDate, err = time.Parse(time.RFC3339, "2099-12-25T14:30:49Z")
	require.NoError(t, err)

	serverCertificate := &ssh.Certificate{
		Nonce:       []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, // dummy value only
		Key:         serverPublicKey,
		Serial:      100,
		CertType:    ssh.HostCert,
		ValidAfter:  uint64(testCertStartDate.Unix()),
		ValidBefore: uint64(testCertExpiryDate.Unix()),
	}

	err = serverCertificate.SignCert(rand.Reader, caSigner)
	require.NoError(t, err)

	serverSigner, err := ssh.NewCertSigner(serverCertificate, serverPrivateKeySigner)
	require.NoError(t, err)

	testSSHHostPrivateKey = serverSigner
	testSSHHostCertificate = serverCertificate

	// Generate client key and certificate
	clientPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clientPrivateKeySigner, err := ssh.NewSignerFromSigner(clientPrivateKey)
	require.NoError(t, err)

	clientPublicKey, err := ssh.NewPublicKey(&clientPrivateKey.PublicKey)
	require.NoError(t, err)

	clientCertificate := &ssh.Certificate{
		Nonce:           []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, // dummy value only
		Key:             clientPublicKey,
		Serial:          200,
		CertType:        ssh.UserCert,
		ValidAfter:      0,
		ValidBefore:     math.MaxUint64,
		ValidPrincipals: []string{"nobody", "testuser"},
	}

	err = clientCertificate.SignCert(rand.Reader, caSigner)
	require.NoError(t, err)

	clientSigner, err := ssh.NewCertSigner(clientCertificate, clientPrivateKeySigner)
	require.NoError(t, err)

	testSSHClientPrivateKey = clientSigner
}

func TestParseSSHCert(t *testing.T) {
	// Generating the keys is an expensive operation so we do it once and cache the results
	// for use by multiple tests. This makes the unit tests run faster.
	testOnce.Do(func() {
		initTestKeys(t)
	})

	cert := parseSSHCert(testSSHHostCertificate)
	require.NotNil(t, cert)

	require.Equal(t, ProtocolSSH, cert.Protocol)
	require.Equal(t, "ssh-rsa", cert.KeyType)
	require.Contains(t, cert.Description, "ssh-rsa certificate serial 100")
	require.Equal(t, testSSHHostCertificate.Marshal(), cert.Raw)
}

func TestGetSSHCertificateChain(t *testing.T) {
	// Generating the keys is an expensive operation so we do it once and cache the results
	// for use by multiple tests. This makes the unit tests run faster.
	testOnce.Do(func() {
		initTestKeys(t)
	})

	// Create an SSH server configuration
	config := &ssh.ServerConfig{
		//NoClientAuth: true,

		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},

		// Since this is only a test server, it does minimal validation
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{
				// Record the public key used for authentication.
				Extensions: map[string]string{
					"pubkey-fp": ssh.FingerprintSHA256(pubKey),
				},
			}, nil
		},

		// For debugging
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			Debug.Printf("TestParseSSHCert AuthLogCallback method %v, error %v", method, err)
		},
	}

	config.AddHostKey(testSSHHostPrivateKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0") // using port ":0" means pick an unused port to listen on
	require.NoError(t, err)
	defer listener.Close()

	var listenerError error

	go func() {
		socket, err := listener.Accept()
		if err != nil {
			listenerError = err
			return
		}

		// Handshake and then immediately close
		conn, _, _, err := ssh.NewServerConn(socket, config)
		if err != nil {
			listenerError = err
			return
		}

		if conn != nil {
			conn.Close()
		}
	}()

	// Now connect to the listener
	host, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)

	connection := Connection{
		Host:     host,
		IP:       net.ParseIP(host),
		Port:     parsePort(ProtocolSSH, port),
		Protocol: ProtocolSSH,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	options := &Options{
		ConfigSSH: &ssh.ClientConfig{
			Auth: []ssh.AuthMethod{ssh.PublicKeys(testSSHClientPrivateKey)},
			User: "testuser",
		},
	}

	chain, err := connection.GetCertificateChain(ctx, options)
	require.NoError(t, err)
	require.NotNil(t, chain)

	require.NoError(t, listenerError, "Unexpected error on background listener")

	require.Len(t, chain, 1)
	serverCert := chain[0]

	require.Equal(t, ProtocolSSH, serverCert.Protocol)
	require.Equal(t, "ssh-rsa", serverCert.KeyType)
	require.Contains(t, serverCert.Description, "ssh-rsa certificate serial 100")
	require.Equal(t, testCertStartDate.String(), serverCert.StartDate.String())
	require.Equal(t, testSSHHostCertificate.Marshal(), serverCert.Raw)
}
