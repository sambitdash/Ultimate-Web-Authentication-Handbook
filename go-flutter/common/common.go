/*
Common TLS/HTTPS helpers for loading provider certificates and keys,
building TLS server/client configuration, and creating preconfigured
HTTP/HTTPS server instances.

Function summary:

GetProviderCertAndKey loads a private key and certificate from files and
returns them as parsed Go crypto types.

addCertificates reads PEM certificates from a file and appends them to a
tls.Certificate value.

GetTLSCert builds a tls.Certificate using the server certificate chain,
CA certificates, and the private key.

GetHTTPSClient creates an HTTP client that trusts the certificates in a
given CA file.

SetupHTTPSServer creates an HTTPS server with TLS 1.3 and a new handler mux.

SetupHTTPServer creates a basic HTTP server with a new handler mux for given server name and port.
*/

package common

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"

	"github.com/youmark/pkcs8"
)

func GetProviderCertAndKey(certpath, keypath string, keypass []byte) (key *rsa.PrivateKey, cert *x509.Certificate, err error) {
	var data []byte
	if data, err = os.ReadFile(keypath); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			if key, err = pkcs8.ParsePKCS8PrivateKeyRSA(block.Bytes, keypass); err != nil {
				return
			}
		}
	}
	if data, err = os.ReadFile(certpath); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			cert, err = x509.ParseCertificate(block.Bytes)
		}
	}
	return
}

// addCertificates loads PEM certificates from certpath and appends them to c.
func addCertificates(certpath string, c *tls.Certificate) (err error) {
	var (
		data  []byte
		block *pem.Block
	)
	if data, err = os.ReadFile(certpath); err == nil {
		for block, data = pem.Decode(data); block != nil; block, data = pem.Decode(data) {
			if block.Type == "CERTIFICATE" {
				c.Certificate = append(c.Certificate, block.Bytes)
			}
		}
	}
	return
}

/*
Server certificate
*/
// GetTLSCert loads certificate chain data and a private key into a tls.Certificate.
func GetTLSCert(capath, certpath, keypath string, keypass []byte) (c *tls.Certificate, err error) {
	var (
		data  []byte
		block *pem.Block
		cert  tls.Certificate
	)

	if err = addCertificates(certpath, &cert); err == nil {
		if err = addCertificates(capath, &cert); err == nil {
			if data, err = os.ReadFile(keypath); err == nil {
				if block, _ = pem.Decode(data); block != nil {
					if cert.PrivateKey, _, err = pkcs8.ParsePrivateKey(block.Bytes, keypass); err == nil {
						if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err == nil {
							c = &cert
						}
					}
				} else {
					err = fmt.Errorf("no private key data found")
				}
			}
		}
	}
	return
}

// SetupHTTPSServer creates an HTTPS server and mux configured for TLS 1.3.
func SetupHTTPSServer(srvName string, capath string, certpath string,
	keypath string, keypass []byte, port string,
) (*http.Server, *http.ServeMux, error) {
	cert, err := GetTLSCert(capath, certpath, keypath, keypass)
	if err != nil {
		return nil, nil, err
	}

	tlsConfig := &tls.Config{
		ServerName:   srvName,
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*cert},
	}

	mux := http.NewServeMux()
	return &http.Server{
		Addr:      ":" + port,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}, mux, nil
}

// SetupHTTPServer creates a basic HTTP server and mux for the given server name and port.
func SetupHTTPServer(srvName string, port string) (*http.Server, *http.ServeMux, error) {
	if handlerMux := http.NewServeMux(); handlerMux != nil {
		return &http.Server{
			Addr:    srvName + ":" + port,
			Handler: handlerMux,
		}, handlerMux, nil
	}
	return nil, nil, fmt.Errorf("failed to create handler mux")
}

// GetHTTPSClient creates an HTTP client using the CA file at capath as Root CAs.
func GetHTTPSClient(capath string) (client *http.Client, err error) {
	var (
		tlsConfig tls.Config
		data      []byte
	)
	if data, err = os.ReadFile(capath); err == nil {
		var block *pem.Block
		certpool := x509.NewCertPool()
		for block, data = pem.Decode(data); block != nil; block, data = pem.Decode(data) {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				certpool.AddCert(cert)
			}
		}
		tlsConfig.RootCAs = certpool
	} else {
		return
	}
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
		},
	}
	return
}
