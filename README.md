# cert-herder

Cert-herder is a certificate discovery tool to help penetration testers and system administrators who need to discover the digital certificates which exist in an environment. This allows the user to easily gather certificates in order to identify expired certificates, certificates with weak encryption algorithms and other issues of concern.

Given a list of places (URLs or IP:port combinations), the tool will perform a client handshake to each server in turn and will gather the certificate chain for each one.

The primary focus of the tool is TLS X.509 certificate chains, however there is experimental support for SSH certificates too. In the SSH case, the tool ignores SSH servers which don't present a certificate: this is deliberate as the tool is only interested in certificates (see ssh-keyscan for a tool that can query SSH keys).

This tool is under development and may change.

## Usage Notice

This tool is provided only to help users to manage certificates in their own environments where they are permitted to do so. Only the public part of the certificate is recorded, and only by means of performing a valid handshake over a protocol supported by the server.

However, use of this tool without the consent of the system owner might be against the law. For example, excessive handshaking may put systems under undue stress and may consitute a denial of service attack (although the tool is coded to rate-limit scans of the same IP address). It is the user's responsibility to secure all necessary consent to run the tool and to act in accordance with all applicable laws. The author accepts no liability for any consequences of misuse of this tool.

## Goals

1. To perform handshakes with a range of servers and discover the certificates used by those servers.

2. Discovery includes the ability to store copies of the certificates obtained in other locations (such as files on disk) for further analysis.

## Non-Goals

1. Stealth is not a goal of this tool. Large-scale sweeps of a network are noisy and may attract attention from network intrusion detection systems. Also, in some cases this tool will cause errors to be logged on the servers being scanned. This tool is intended for users who have permission to enumerate certificates in their environment, either system administrators or penetration testers conducting tests with the owner's consent (see Usage Notice above).

2. It is not a goal of this tool to perform detailed analysis of the certificates obtained. The tool is only concerned with discovering and gathering certificates ("herding" them).

3. It is not a goal of this tool to expose every possible configuration option via the example command-line tool provided. The mainline code is intended to do just enough to handle the most common use cases. For ultimate control over how the certificates are discovered and processed, the discovery package can be used as a library in your own golang code. Refer to the main.go code to see how it can be called.

## Discovery

Certificates are discovered from the places specified in a comma-separated list in the `-places` parameter. Each place can be:
- An IP address
- An IP address and port number
- An IP CIDR address block (e.g. "192.168.1.0/28")
- An IP CIDR address block and port number (e.g. "192.168.1.0/28:8443")
- An HTTPS URL (e.g. "https://www.example.com")
- An SSH URL (e.g. "ssh://172.16.2.53")

Whether to speak SSH or TLS protocol is inferred as follows:
- For a URL, the URL scheme prefix: "https://" or "ssh://"
- Otherwise, the port number: 22 for SSH, or else TLS

## Output

By default, a summary of each certificate is output on the console.

If the `-output-dir` parameter is specified then certificates are written into files in the specified directory. A default file name pattern will be generated, but you can specify a golang template in the `-output-name-template` parameter to control how the names are generated.

All created output files and directories will have permissions 0600.

## Examples

```
cert-herder -places 172.16.2.53:443

cert-herder -places https://www.example.com
cert-herder -places https://www.example.com:8443
cert-herder -places ssh://172.16.2.53

cert-herder -places https://www.example.com,https://192.168.75.24
cert-herder -places https://www.example.com,https://192.168.75.24,ssh://172.16.2.53
```

The following example demonstrates using cert-header to scan a CIDR block of IP addresses on port 8443:
```
cert-herder -places 192.168.1.0/28:8443
```

When scanning multiple places (whether using CIDR notation or not), it helps the scan to run faster if you allow it to run in parallel. The -c parameter controls the maximum number of connections that can be made in parallel:
```
cert-herder -places 192.168.1.0/28:8443 -c 16
```

When writing certificates to an output directory for later analysis (output directory must exist and be writeable by the user):
```
go build && ./cert-herder -places https://www.example.com -output-dir /tmp/certs
```

## What about new features?

For simple extensions, feel free to submit a pull request.
