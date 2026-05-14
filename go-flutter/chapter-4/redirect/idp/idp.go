package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"howa.in/common"
)

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	redirectURL := r.URL.Query().Get("redirectURL")

	// Check if approved cookie is set
	cookie, err := r.Cookie("approved")
	if err == nil && cookie.Value == "true" {
		if redirectURL != "" {
			http.Redirect(w, r, redirectURL+"?ticket=approved", http.StatusFound)
		} else {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`<p>Error: no redirectURL is specified</p>`))
		}
		return
	}

	// Check if approve button was clicked
	if r.URL.Query().Get("approve") == "true" {
		http.SetCookie(w, &http.Cookie{
			Name:     "approved",
			Value:    "true",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
		})
		if redirectURL != "" {
			http.Redirect(w, r, redirectURL+"?ticket=approved", http.StatusFound)
		} else {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`<p>Error: no redirectURL is specified</p>`))
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	html := `
		<h1>Approve Access</h1>
		<form method="GET">
			<input type="hidden" name="approve" value="true">`
	if redirectURL != "" {
		html += `
			<input type="hidden" name="redirectURL" value="` + redirectURL + `">`
	}
	html += `
			<button type="submit">Approve</button>
		</form>
	`
	w.Write([]byte(html))
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
