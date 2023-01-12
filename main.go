package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/suyashkumar/ssl-proxy/gen"
	"github.com/suyashkumar/ssl-proxy/reverseproxy"
)

var (
	to       = flag.String("to", "http://127.0.0.1:80", "the address and port for which to proxy requests to")
	fromURL  = flag.String("from", "0.0.0.0:443", "the tcp address and port this proxy should listen for requests on")
	certFile = flag.String("cert", "", "path to a tls certificate file. If not provided, ssl-proxy will generate one for you in ~/.ssl-proxy/")
	keyFile  = flag.String("key", "", "path to a private key file. If not provided, ssl-proxy will generate one for you in ~/.ssl-proxy/")
)

const (
	DefaultCertFile = "cert.pem"
	DefaultKeyFile  = "key.pem"
	HTTPSPrefix     = "https://"
	HTTPPrefix      = "http://"
)

func main() {
	flag.Parse()

	validCertFile := *certFile != ""
	validKeyFile := *keyFile != ""

	// Determine if we need to generate self-signed certs
	if !validCertFile || !validKeyFile {
		// Use default file paths
		*certFile = DefaultCertFile
		*keyFile = DefaultKeyFile

		log.Printf("No existing cert or key specified, generating some self-signed certs for use (%s, %s)\n", *certFile, *keyFile)

		// Generate new keys
		certBuf, keyBuf, fingerprint, err := gen.Keys(365 * 24 * time.Hour)
		if err != nil {
			log.Fatal("Error generating default keys", err)
		}

		certOut, err := os.Create(*certFile)
		if err != nil {
			log.Fatal("Unable to create cert file", err)
		}
		certOut.Write(certBuf.Bytes())

		keyOut, err := os.OpenFile(*keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatal("Unable to create the key file", err)
		}
		keyOut.Write(keyBuf.Bytes())

		log.Printf("SHA256 Fingerprint: % X", fingerprint)

	}

	// Ensure the to URL is in the right form
	if !strings.HasPrefix(*to, HTTPPrefix) && !strings.HasPrefix(*to, HTTPSPrefix) {
		*to = HTTPPrefix + *to
		log.Println("Assuming -to URL is using http://")
	}

	// Parse toURL as a URL
	toURL, err := url.Parse(*to)
	if err != nil {
		log.Fatal("Unable to parse 'to' url: ", err)
	}

	// Setup reverse proxy ServeMux
	p := reverseproxy.Build(toURL)
	mux := http.NewServeMux()
	mux.Handle("/", p)

	log.Printf(green("Proxying calls from https://%s (SSL/TLS) to %s"), *fromURL, toURL)

	// Configure TLS to reasonably secure defaults
	tlsCfg := new(tls.Config)
	tlsCfg.MinVersion = tls.VersionTLS12
	// Limit cipher suites available
	tlsCfg.CipherSuites = []uint16{
		// TLS 1.3 cipher suites.
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,

		// TLS 1.2 cipher suites.
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}

	// Serve TLS using provided/generated certificate files
	proxyServer := &http.Server{
		Addr:      *fromURL,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}
	log.Fatal(proxyServer.ListenAndServeTLS(*certFile, *keyFile))
}

// green takes an input string and returns it with the proper ANSI escape codes to render it green-colored
// in a supported terminal.
// TODO: if more colors used in the future, generalize or pull in an external pkg
func green(in string) string {
	return fmt.Sprintf("\033[0;32m%s\033[0;0m", in)
}
