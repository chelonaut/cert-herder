package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/chelonaut/cert-herder/discovery"
)

const (
	defaultOutputNameTemplate = `cert_{{.DiscoveredChain.Connection.IP.String}}_` +
		`{{.DiscoveredChain.Connection.Port}}_` +
		`{{.Certificate.Description}}.der`
)

func main() {
	///////////////////////////////////////////////////////////////////
	// Parse command-line flags
	///////////////////////////////////////////////////////////////////
	maxParallelConnections := flag.Int("c", 1, "The maximum number of parallel connections to make")
	debug := flag.Bool("debug", false, "Enable debug logging")
	outputDir := flag.String("output-dir", "", "The directory where gathered certificates will be written. If omitted, no file output will be created.")
	outputNameTemplate := flag.String("output-name-template", defaultOutputNameTemplate, "A golang template specifying how to generate the file names for files written to output-dir.")
	places := flag.String("places", "", "REQUIRED: A comma-separated list of places to discover certificates, e.g. https://127.0.0.1:8443,ssh://127.0.0.1")
	sshUser := flag.String("ssh-user", "nobody", "The user ID to use when connecting via SSH")
	sshPassword := flag.String("ssh-password", "", "The password to use when connecting via SSH (NOT recommended)")
	timeout := flag.Int("timeout", 5000, "Maximum number of milliseconds to wait for a successful connection and handshake")
	flag.Parse()

	// Error for any missing required flags
	if *places == "" {
		flag.PrintDefaults()
		os.Exit(2)
	}

	if *debug {
		discovery.Debug = log.New(os.Stderr, "DEBUG: ", log.LstdFlags)
	}

	///////////////////////////////////////////////////////////////////
	// Build and validate the options to discover certificates
	///////////////////////////////////////////////////////////////////
	options := &discovery.Options{
		Places:                     strings.Split(*places, ","),
		ConfigSSH:                  &ssh.ClientConfig{},
		ConfigTLS:                  &tls.Config{},
		MaximumParallelConnections: *maxParallelConnections,
		Timeout:                    time.Duration(*timeout) * time.Millisecond,
	}

	if *sshUser != "" {
		options.ConfigSSH.User = *sshUser
	}

	if *sshPassword != "" {
		options.ConfigSSH.Auth = append(options.ConfigSSH.Auth, ssh.Password(*sshPassword))
	}

	if *outputDir != "" {
		templ, err := template.New("OutputNameTemplate").Parse(*outputNameTemplate)
		if err != nil {
			fmt.Printf("Unable to parse output name template '%v': %v", *outputNameTemplate, err)
			os.Exit(2)
		}

		outputDirCallback := func(dc *discovery.DiscoveredChain) {
			// Skip any cases where errors occurred
			if dc.Error != nil {
				return
			}

			// Process each certificate in the chain
			for certIndex, cert := range dc.Chain {
				fileName := filepath.Join(*outputDir, generateOutputFileName(templ, cert, certIndex, dc))

				file, err := os.OpenFile(fileName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					fmt.Printf("WARNING: Unable to create file '%v' for writing: %v\n", fileName, err)
					continue
				}

				_, err = file.Write(cert.Raw)
				if err != nil {
					fmt.Printf("WARNING: Unable to write to file '%v': %v\n", fileName, err)
					continue
				}

				file.Close()

				fmt.Printf("Wrote %v %v:%v certificate %v to %v\n",
					dc.Connection.Protocol,
					dc.Connection.IP.String(),
					dc.Connection.Port,
					cert.Description,
					fileName)
			}

		}

		options.DiscoveredChainFuncs = append(options.DiscoveredChainFuncs, outputDirCallback)
	}

	if len(options.DiscoveredChainFuncs) == 0 {
		options.DiscoveredChainFuncs = []discovery.DiscoveredChainFunc{displayCallback}
	}

	///////////////////////////////////////////////////////////////////
	// Now discover certificates from the specified places
	///////////////////////////////////////////////////////////////////
	err := discovery.Run(options)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func displayCallback(dc *discovery.DiscoveredChain) {
	// First check for errors
	if dc.Error != nil {
		fmt.Printf("%s: Failed to get certificate chain: %v\n\n", dc.Connection, dc.Error)
		return
	}

	// Note: to try and reduce the interleaving of output on the console, we build the whole
	// message in a buffer and write it in one call.
	result := fmt.Sprintf("%s: Found certificate chain...\n", dc.Connection)
	for index, cert := range dc.Chain {
		result += fmt.Sprintf(" %v: %v\n", index, cert.Description)
	}

	fmt.Println(result)
}

func generateOutputFileName(templ *template.Template, cert *discovery.Certificate, chainIndex int, dc *discovery.DiscoveredChain) string {
	buffer := bytes.NewBufferString("")
	var err error

	err = templ.Execute(buffer, struct {
		Certificate     *discovery.Certificate
		ChainIndex      int
		DiscoveredChain *discovery.DiscoveredChain
	}{
		Certificate:     cert,
		ChainIndex:      chainIndex,
		DiscoveredChain: dc,
	})
	if err != nil {
		panic("Failed to generate output filename: " + err.Error())
	}

	return makeSafeFileName(buffer.String())
}

// makeSafeFileName removes characters which are unsuitable for use in
// a file name on the current platform and truncates the file name length
// to fit platform and filesystem limitations.
func makeSafeFileName(s string) string {
	const maxLen = 200 // slightly arbitrary but must be <= 254 for most modern filesystems

	// First, tidy the file path to a clean representation
	result := filepath.Clean(s)

	// Next, split the path into elements between separators and check each element.
	elements := filepath.SplitList(result)
	newElements := []string{}

	for _, element := range elements {
		newElements = append(newElements, makeSafeFileElement(element))
	}

	result = filepath.Join(newElements...)

	// Also avoid starting a file name with a period as this has a special meaning on UNIX
	// and UNIX-like systems.
	dir := filepath.Dir(result)
	base := filepath.Base(result)

	if base[0] == '.' {
		result = filepath.Join(dir, base[1:])
	}

	// Ensure the resulting name isn't too long, as X.509 distinguished names can be very long.
	if len(result) > maxLen {
		result = result[:maxLen]
	}

	return result
}

// makeSafeFileElement removes characters which are unsuitable for use in
// an element of a file name. An element is anything after a volume name
// and between a separator (e.g. slash).
func makeSafeFileElement(s string) string {
	// The following characters cause varying degrees of inconveience on
	// various platforms and are best avoided.
	replacements := []string{
		`?`, `-`,
		`%`, `-`,
		`*`, `-`,
		`:`, `-`,
		`|`, `-`,
		`"`, `-`,
		`<`, `-`,
		`>`, `-`,
		`$`, `-`,
		` `, `_`,
	}
	repl := strings.NewReplacer(replacements...)

	return repl.Replace(s)
}
