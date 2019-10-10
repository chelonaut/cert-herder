package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// In general it's very bad practice to hard-code keys and certificates in this way.
	// However, this key and certificate are used only for unit tests and are not important.
	// Don't reuse these anywhere else!
	testTLSPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA5rMDMg3q5ydKbHwyZRXQG8dsUWorxlLW84cibKTpM5+Y9O8m
/Ru1vjIWuaTPvPDZQRETgC8c32WU6ZjaAE3TyiThSomebyAQvx5LF44c7VyxCb2U
HOziJQ2Bhvii4zLMuiG9S/Q7FwJDdFX43kY3W2nzLvCcHa+jlXto3zIT2mqE4rTD
xbEWJbcZX3TN5u6T5tvia9EwFLYMAV28qtW+skz4COg0/rsJG3itoRG9NJT2GlmQ
xWbd+A8T8R/RmUYqrMY/5nei/6meKaAgv42k6Ye1WrLD2cd6w/0OWvRJ4wCsYUbG
2Y+Pmn8nb2DAvD/HuCM5J742pFDO3fCfdCa5XQIDAQABAoIBAA6whVqRkkyHrvB7
dAYFvouWRipk9Uaajb9R8noygfrchbPK6pOhSRBERjgp62RffaXr/W7jERaUdEfv
iKoOSpcLhCDn5GO1CfvxZNyqGuNuTIOPQ7gXyUqMspuyh0SqPmj3rwMAGScc6Mim
lMMqe2nhtC9f+MDXJzZkdkgH+0Wj9bjvapA8LxxF3AEzZk8bnieBZ1mnm2juzmce
vsxMVqD2dgvMVjjTvOnvYgRO5FtQHsg+ed51TqvyGU6XpKItRlWOSwO2u2i2mjIH
BMyRujgBAVrEl4ZNtpUJ2zU5S5hh3H5flZunbK4MFH9HJj0FUrKCL9bBcLdNloF2
3SMZh+ECgYEA/ndsojlfwtdvPPHJGU+YNJxuEcLH1DiZ1jKpDNQ8m9MQPNUKT4KN
FWsmLQvFuYndu7/uPJrZU2U1j3fn6t5YARZu3QrZGfuCbH4V01A1PKF2OfdHkCCF
kxJYWt7pZvGwToaUPuAlPVRBAkrwrkmK0Hm86Gt3M/PnPVpNdWEeC5kCgYEA6Bbr
5XMeob2BFJ5LPLA/qGiTzC2rvV42oUqd/lwE3ZfS+ArszW1WBvjBLL2643J+K2xw
eZd+cSkaGaBcU9DWNLOQtdwQcte8w1R530gNFieaI/uvR2whRo0dek3ws9kdhIy4
i1Vu9pfo9l/IImNGQJA+S8UYHNaskh/daCjVFmUCgYEAy54SLkkMqGMs3q52hStc
lpSpusqKjfVwm6ZUATD/Ao1ES/kI1BCaBg6EML1fzRRVejudTZ920TWGQzPmPtkF
wHEL6xIYIKNRfLDzk/B1ePuWF9IX0GtFlyaxzpzaVQaGVn93tkwzYDy//C6tIjk0
u5b+I1iCvO6pFT3iB0/b89kCgYEAwiXCifumKTjkjQHqAEeTyOZKlOezncL9Qimw
RwJlE5WY5uQEucf3yfc3aZ0BhJjXUK3y3NRM8o6mhb9u3LJ7LjT0Hh2MKPWts1ys
YorcX6cbO3SkaMPchi8v9IrUiy5ZkfNBwVTjcSccu1Tej12qfAHuCuZCSIWQcOB1
D1fxAT0CgYEAnAJvgOsZIPw1oS7Nk2diwy8tDMFh7bxZlD9z2mJX9Wp+pgyacGim
y2i4y+bZKkvPaln0JljZV5RebB6D+PHmrKmvvRlvCneWRG3DnQSjxe655mFlzaOL
DzrQ5+lI+tZYajKH2VolrtjE8G4kzWOQVL2msb5bP391MdR69A38uvQ=
-----END RSA PRIVATE KEY-----
`

	testCertificate = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIJAJYQOWVnh+fnMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNV
BAMMD3d3dy5leGFtcGxlLmNvbTAgFw0xODEyMzExNjEzMzdaGA8yMTE4MTIwNzE2
MTMzN1owGjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA5rMDMg3q5ydKbHwyZRXQG8dsUWorxlLW84cibKTp
M5+Y9O8m/Ru1vjIWuaTPvPDZQRETgC8c32WU6ZjaAE3TyiThSomebyAQvx5LF44c
7VyxCb2UHOziJQ2Bhvii4zLMuiG9S/Q7FwJDdFX43kY3W2nzLvCcHa+jlXto3zIT
2mqE4rTDxbEWJbcZX3TN5u6T5tvia9EwFLYMAV28qtW+skz4COg0/rsJG3itoRG9
NJT2GlmQxWbd+A8T8R/RmUYqrMY/5nei/6meKaAgv42k6Ye1WrLD2cd6w/0OWvRJ
4wCsYUbG2Y+Pmn8nb2DAvD/HuCM5J742pFDO3fCfdCa5XQIDAQABo1AwTjAdBgNV
HQ4EFgQUAqgHMApIiHR5PbW+abue+BEebLEwHwYDVR0jBBgwFoAUAqgHMApIiHR5
PbW+abue+BEebLEwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAGEoJ
padotG75PEvaMxIxeAbF9aiaDKLVj3/CS2DHrPedfTKsGrk4OI++cNTvl8EWEa8H
AAdluAXVQUOYoFMpEpUiZsUWPk8Gp3uJV0xSmzw8GufLSzy5OvB6MgH6Pxj7utR/
Pu/ywPziqmvzFAgvW7OC3ltaxdyfZ8YQnBxvcu8YiEHyLphP8VYeVFSTwSiI6/PM
eYj19asZ512cFC8hKETLi0wuN5usgUOqmrcnWUbObN1eKs/l/WYlUkuLBrG0YTGF
YGWx6gf2wQncbhlRU1X0L6x3ESpgIJUMy36zP4RH/p+gTEpc796++i9lU6UksXGC
5ii6QiGb1adbfpjlkg==
-----END CERTIFICATE-----`

	testTLSCertificateStartDate  = `2018-12-31 16:13:37 +0000 UTC`
	testTLSCertificateExpiryDate = `2118-12-07 16:13:37 +0000 UTC`
)

func TestParseX509Cert(t *testing.T) {
	block, _ := pem.Decode([]byte(testCertificate))
	require.NotNil(t, block)

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	parsedCert := parseX509Cert(x509Cert)
	require.NotNil(t, parsedCert)

	require.Equal(t, ProtocolTLS, parsedCert.Protocol, "Unexpected Protocol")
	require.Equal(t, "RSA", parsedCert.KeyType, "Unexpected KeyType")
	require.Equal(t, "SHA256-RSA", parsedCert.SignatureType, "Unexpected SignatureType")
	require.Contains(t, parsedCert.Description, "CN=www.example.com", "Description does not contain expected substring")
}

func TestGetTLSCertificateChain(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(testCertificate), []byte(testTLSPrivateKey))
	require.NoError(t, err)

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", ":0", cfg) // using port ":0" means pick an unused port to listen on
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		socket, _ := listener.Accept()
		socket.Write([]byte("goodbye"))
		socket.Close()
	}()

	// Now connect to the listener
	host, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)

	connection := Connection{
		Host:     host,
		IP:       net.ParseIP(host),
		Port:     parsePort(ProtocolTLS, port),
		Protocol: ProtocolTLS,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	chain, err := connection.GetCertificateChain(ctx, &Options{})
	require.NoError(t, err)
	require.NotNil(t, chain)

	require.Len(t, chain, 1)

	require.Equal(t, ProtocolTLS, chain[0].Protocol, "Unexpected Protocol")
	require.Equal(t, "RSA", chain[0].KeyType, "Unexpected KeyType")
	require.Equal(t, "SHA256-RSA", chain[0].SignatureType, "Unexpected SignatureType")
	require.Contains(t, chain[0].Description, "CN=www.example.com", "Description does not contain expected substring")
}

func TestRunTLS(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(testCertificate), []byte(testTLSPrivateKey))
	require.NoError(t, err)

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", ":0", cfg) // using port ":0" means pick an unused port to listen on
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		socket, _ := listener.Accept()
		socket.Write([]byte("goodbye"))
		socket.Close()
	}()

	// Now run the discovery
	callbackCount := 0
	options := &Options{
		Places: []string{"https://" + listener.Addr().String()},

		DiscoveredChainFuncs: []DiscoveredChainFunc{
			func(dc *DiscoveredChain) {
				callbackCount++

				if !assert.NoError(t, dc.Error) {
					return
				}
				if !assert.NotNil(t, dc.Chain) {
					return
				}

				if !assert.Len(t, dc.Chain, 1) {
					return
				}

				if !assert.Equal(t, ProtocolTLS, dc.Chain[0].Protocol, "Unexpected Protocol") {
					return
				}
				if !assert.Equal(t, "RSA", dc.Chain[0].KeyType, "Unexpected KeyType") {
					return
				}
				if !assert.Equal(t, "SHA256-RSA", dc.Chain[0].SignatureType, "Unexpected SignatureType") {
					return
				}
				if !assert.Contains(t, dc.Chain[0].Description, "CN=www.example.com", "Description does not contain expected substring") {
					return
				}
				if !assert.Equal(t, testTLSCertificateStartDate, dc.Chain[0].StartDate.String(), "Unexpected certificate start date") {
					return
				}
				if !assert.Equal(t, testTLSCertificateExpiryDate, dc.Chain[0].ExpiryDate.String(), "Unexpected certificate expiry date") {
					return
				}
			},
		},
	}

	err = Run(options)
	require.NoError(t, err)
	require.Equal(t, 1, callbackCount, "Chain validation callback should have been called exactly once")
}

func TestRunTLSError(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(testCertificate), []byte(testTLSPrivateKey))
	require.NoError(t, err)

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", ":0", cfg) // using port ":0" means pick an unused port to listen on
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		socket, _ := listener.Accept()
		socket.Write([]byte("goodbye"))
		socket.Close()
	}()

	// Now run the discovery
	callbackCount := 0

	options := &Options{
		Places: []string{"https://" + listener.Addr().String()},

		DiscoveredChainFuncs: []DiscoveredChainFunc{
			func(dc *DiscoveredChain) {
				callbackCount++

				// There must be an error here due to bad protocol versions
				if !assert.Error(t, dc.Error) {
					return
				}
				if !assert.Contains(t, dc.Error.Error(), "unsupported protocol") {
					return
				}

				// There must be no chain due to the error
				if !assert.Nil(t, dc.Chain) {
					return
				}
			},
		},

		ConfigTLS: &tls.Config{
			MinVersion: 9999,
			MaxVersion: 9999,
		},

		Timeout: 5 * time.Second,
	}

	err = Run(options)
	require.NoError(t, err)
	require.Equal(t, 1, callbackCount, "Chain validation callback should have been called exactly once")
}

// This test will only work if you have internet access so you can resolve via DNS
// and connect to https://www.amazon.com. On an isolated network this test will fail.
func TestGetTLSCertificateChainWellKnownSite(t *testing.T) {
	// Connect to a well-known website to test DNS resolution
	options := &Options{
		Places: []string{"https://www.amazon.com"},
	}

	connections, err := options.GetConnections()
	require.NoError(t, err)
	require.True(t, len(connections) >= 1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connection := connections[0]
	chain, err := connection.GetCertificateChain(ctx, &Options{})
	require.NoError(t, err)
	require.NotNil(t, chain)

	require.True(t, len(chain) >= 1)

	require.Contains(t, chain[0].Description, "CN=www.amazon.com", "Description does not contain expected substring")
}
