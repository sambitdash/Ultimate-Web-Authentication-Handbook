package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"howa.in/common"
)

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	// Check if approve button was clicked
	if r.URL.Query().Get("approve") == "true" {
		http.SetCookie(w, &http.Cookie{
			Name:        "__Host-approved",
			Value:       "true",
			Path:        "/",
			Secure:      true,
			HttpOnly:    true,
			SameSite:    http.SameSiteNoneMode,
			Partitioned: true,
		})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<p>Access Approved</p>`))
		return
	}

	// Check if approved cookie is set
	cookie, err := r.Cookie("__Host-approved")
	if err == nil && cookie.Value == "true" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<p>Access Approved</p>`))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`
		<h1>Approve Access</h1>
		<form method="GET">
			<input type="hidden" name="approve" value="true">
			<button type="submit">Approve</button>
		</form>
	`))
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
		ServerName:   "idp.local",
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*cert},
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
