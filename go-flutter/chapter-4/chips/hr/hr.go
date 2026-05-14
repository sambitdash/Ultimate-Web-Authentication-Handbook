package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"howa.in/common"
)

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<h1>HR System</h1><iframe src="https://chat.local:8443" width="100%" height="100"></iframe>`))
}

func main() {
	http.HandleFunc("/", handleRoot)

	cert, err := common.GetTLSCert(
		"../../certs/server/scas.crt",
		"../../certs/server/mysrv.local.crt",
		"../../certs/server/mysrv.local.key",
		[]byte("password"))
	if err != nil {
		log.Default().Fatal(err)
	}

	tlsConfig := &tls.Config{
		ServerName:   "hr.mysrv.local",
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*cert},
	}

	server := &http.Server{
		Addr:      ":8444",
		TLSConfig: tlsConfig,
	}

	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
