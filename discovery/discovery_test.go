package discovery

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostToIPs(t *testing.T) {
	ips, err := hostToIPs("127.0.0.1")
	require.NoError(t, err)
	require.Len(t, ips, 1)
	require.Equal(t, net.ParseIP("127.0.0.1"), ips[0])
}

func TestHostToIPsCIDR(t *testing.T) {
	ips, err := hostToIPs("10.0.0.0/28")
	require.NoError(t, err)

	// It might look odd to only return 14 IPs for a /28 subnet, but
	// remember we are only interested in unicast addresses that could
	// plausibly be assigned to a machine. In particular note that:
	//   - The base subnet address 10.0.0.0 is not usually assigned to anything.
	//   - The broadcast address 10.0.0.15 isn't usable for unicast SSH or TLS.
	require.Len(t, ips, 14)
	require.Contains(t, ips, net.ParseIP("10.0.0.1"))
	require.Contains(t, ips, net.ParseIP("10.0.0.2"))
	require.Contains(t, ips, net.ParseIP("10.0.0.3"))
	require.Contains(t, ips, net.ParseIP("10.0.0.4"))
	require.Contains(t, ips, net.ParseIP("10.0.0.5"))
	require.Contains(t, ips, net.ParseIP("10.0.0.6"))
	require.Contains(t, ips, net.ParseIP("10.0.0.7"))
	require.Contains(t, ips, net.ParseIP("10.0.0.8"))
	require.Contains(t, ips, net.ParseIP("10.0.0.9"))
	require.Contains(t, ips, net.ParseIP("10.0.0.10"))
	require.Contains(t, ips, net.ParseIP("10.0.0.11"))
	require.Contains(t, ips, net.ParseIP("10.0.0.12"))
	require.Contains(t, ips, net.ParseIP("10.0.0.13"))
	require.Contains(t, ips, net.ParseIP("10.0.0.14"))
}

func TestPlaceToConnectionsIPOnly(t *testing.T) {
	connections, err := placeToConnections("127.0.0.1")
	require.NoError(t, err)
	require.Len(t, connections, 1)

	require.Equal(t, []*Connection{
		&Connection{
			Host:     "127.0.0.1",
			IP:       net.ParseIP("127.0.0.1"),
			Port:     443,
			Protocol: ProtocolTLS,
		},
	},
		connections)
}

func TestPlaceToConnectionsIPAndPortSSH(t *testing.T) {
	connections, err := placeToConnections("127.0.0.1:22")
	require.NoError(t, err)
	require.Len(t, connections, 1)

	require.Equal(t, []*Connection{
		&Connection{
			Host:     "127.0.0.1",
			IP:       net.ParseIP("127.0.0.1"),
			Port:     22,
			Protocol: ProtocolSSH,
		},
	},
		connections)
}

func TestPlaceToConnectionsIPAndPortTLS(t *testing.T) {
	connections, err := placeToConnections("127.0.0.1:443")
	require.NoError(t, err)
	require.Len(t, connections, 1)

	require.Equal(t, []*Connection{
		&Connection{
			Host:     "127.0.0.1",
			IP:       net.ParseIP("127.0.0.1"),
			Port:     443,
			Protocol: ProtocolTLS,
		},
	},
		connections)
}

func TestPlaceToConnectionsIPSSHURL(t *testing.T) {
	connections, err := placeToConnections("ssh://127.0.0.1")
	require.NoError(t, err)
	require.Len(t, connections, 1)

	require.Equal(t, []*Connection{
		&Connection{
			Host:     "127.0.0.1",
			IP:       net.ParseIP("127.0.0.1"),
			Port:     22,
			Protocol: ProtocolSSH,
		},
	},
		connections)
}

func TestPlaceToConnectionsIPTLSURL(t *testing.T) {
	connections, err := placeToConnections("https://127.0.0.1")
	require.NoError(t, err)
	require.Len(t, connections, 1)

	require.Equal(t, []*Connection{
		&Connection{
			Host:     "127.0.0.1",
			IP:       net.ParseIP("127.0.0.1"),
			Port:     443,
			Protocol: ProtocolTLS,
		},
	},
		connections)
}

func TestPlaceToConnectionsURLBadScheme(t *testing.T) {
	connections, err := placeToConnections("nonsense://127.0.0.1")
	require.Error(t, err)
	require.Len(t, connections, 0)
}

func TestOptionsValidateIPValid(t *testing.T) {
	options := Options{
		Places: []string{"127.0.0.1"},
	}

	err := options.Validate()
	require.NoError(t, err)
}

func TestOptionsValidateIPAndPortValid(t *testing.T) {
	options := Options{
		Places: []string{"127.0.0.1:443"},
	}

	err := options.Validate()
	require.NoError(t, err)
}

func TestOptionsValidateIPAndPortValid2(t *testing.T) {
	options := Options{
		Places: []string{"127.0.0.1:1234"},
	}

	err := options.Validate()
	require.NoError(t, err)
}

func TestOptionsValidateIPURLValid(t *testing.T) {
	options := Options{
		Places: []string{"https://127.0.0.1:1234"},
	}

	err := options.Validate()
	require.NoError(t, err)
}

func TestOptionsValidateIPSSHURLValid(t *testing.T) {
	options := Options{
		Places: []string{"ssh://127.0.0.1"},
	}

	err := options.Validate()
	require.NoError(t, err)
}

func TestOptionsValidateNoPlacesError(t *testing.T) {
	options := Options{}

	err := options.Validate()
	require.Error(t, err)
}

func TestOptionsValidateInvalidSchemeError(t *testing.T) {
	options := Options{
		Places: []string{"dsjdghdg://127.0.0.1"},
	}

	err := options.Validate()
	require.Error(t, err)
}

func TestCopyIPv4(t *testing.T) {
	ip1 := net.ParseIP("10.1.2.3")
	require.NotNil(t, ip1)

	ip2 := copyIP(ip1)
	require.NotNil(t, ip2)

	require.Equal(t, ip1, ip2, "An unequal copy was made")
	require.True(t, &ip1 != &ip2, "IP slices must not point at the same storage")
}

func TestCopyIPv6(t *testing.T) {
	ip1 := net.ParseIP("1122:3344:5566::abcd:efff")
	require.NotNil(t, ip1)

	ip2 := copyIP(ip1)
	require.NotNil(t, ip2)

	require.Equal(t, ip1, ip2, "An unequal copy was made")
	require.True(t, &ip1 != &ip2, "IP slices must not point at the same storage")
}

func TestGetFirstAndLastIP(t *testing.T) {
	tests := []struct {
		Input         string
		ExpectedFirst net.IP
		ExpectedLast  net.IP
	}{
		{"10.0.0.0/31", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.1")},
		{"10.0.0.0/30", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.3")},
		{"10.0.0.0/29", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.7")},
		{"10.0.0.0/28", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.15")},
		{"10.0.0.0/27", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.31")},
		{"10.0.0.0/26", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.63")},
		{"10.0.0.0/25", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.127")},
		{"10.0.0.0/24", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.255")},
		{"10.0.0.0/23", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.1.255")},
		{"10.0.0.0/22", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.3.255")},
		{"10.0.0.0/21", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.7.255")},
		{"10.0.0.0/20", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.15.255")},
		{"10.0.0.0/19", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.31.255")},
		{"10.0.0.0/18", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.63.255")},
		{"10.0.0.0/17", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.127.255")},
		{"10.0.0.0/16", net.ParseIP("10.0.0.0"), net.ParseIP("10.0.255.255")},
		{"10.0.0.0/15", net.ParseIP("10.0.0.0"), net.ParseIP("10.1.255.255")},
		{"10.0.0.0/14", net.ParseIP("10.0.0.0"), net.ParseIP("10.3.255.255")},
		{"10.0.0.0/13", net.ParseIP("10.0.0.0"), net.ParseIP("10.7.255.255")},
		{"10.0.0.0/12", net.ParseIP("10.0.0.0"), net.ParseIP("10.15.255.255")},
		{"10.0.0.0/11", net.ParseIP("10.0.0.0"), net.ParseIP("10.31.255.255")},
		{"10.0.0.0/10", net.ParseIP("10.0.0.0"), net.ParseIP("10.63.255.255")},
		{"10.0.0.0/9", net.ParseIP("10.0.0.0"), net.ParseIP("10.127.255.255")},
		{"10.0.0.0/8", net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{"172.16.0.0/12", net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
	}

	for number, test := range tests {
		firstIP, lastIP, err := getFirstAndLastIPs(test.Input)

		require.NoError(t, err, "test %v failed: unexpected error", number)
		require.NotNil(t, firstIP, "test %v failed: unexpected nil first IP returned", number)
		require.NotNil(t, lastIP, "test %v failed: unexpected nil first IP returned", number)
		require.Equal(t, test.ExpectedFirst, firstIP, "test %v failed: incorrect first IP", number)
		require.Equal(t, test.ExpectedLast, lastIP, "test %v failed: incorrect last IP", number)
	}
}

func TestIncrementIP(t *testing.T) {
	tests := []struct {
		Input          net.IP
		ExpectedOutput net.IP
	}{
		{net.ParseIP("0.0.0.0"), net.ParseIP("0.0.0.1")},
		{net.ParseIP("1.0.0.0"), net.ParseIP("1.0.0.1")},
		{net.ParseIP("1.0.0.1"), net.ParseIP("1.0.0.2")},
		{net.ParseIP("1.0.0.254"), net.ParseIP("1.0.0.255")},
		{net.ParseIP("1.0.0.255"), net.ParseIP("1.0.1.0")},
		{net.ParseIP("10.0.255.255"), net.ParseIP("10.1.0.0")},
		{net.ParseIP("10.255.255.255"), net.ParseIP("11.0.0.0")},
		{net.ParseIP("255.255.255.255"), net.ParseIP("0.0.0.0")}, // wrap-around

		{net.ParseIP("::"), net.ParseIP("::1")},
		{net.ParseIP("::1"), net.ParseIP("::2")},
		{net.ParseIP("::2"), net.ParseIP("::3")},
		{net.ParseIP("::ff"), net.ParseIP("::100")},
		{net.ParseIP("::ffff"), net.ParseIP("::1:0")},
		{net.ParseIP("1234::4321"), net.ParseIP("1234::4322")},
		{net.ParseIP("1234::8765:ffff"), net.ParseIP("1234::8766:0")},
		{net.ParseIP("1234:5678:90ab:cdef:fedc:ba09:8765:4321"), net.ParseIP("1234:5678:90ab:cdef:fedc:ba09:8765:4322")},
		{net.ParseIP("1234:5678:90ab:cdef:fedc:ba09:8765:ffff"), net.ParseIP("1234:5678:90ab:cdef:fedc:ba09:8766:0")},
		{net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), net.ParseIP("::")}, // wrap-around
	}

	for number, test := range tests {
		ip := copyIP(test.Input)
		incrementIP(ip)

		require.NotNil(t, ip, "Test %v failed: nil result returned", number)
		require.Equal(t, test.ExpectedOutput, ip, "Test %v failed: incremented IP is incorrect", number)
	}
}
