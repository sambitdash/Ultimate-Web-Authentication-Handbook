package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"

	"howa.in/common"
)

type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Phone string `json:"phone"`
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if id == "jdoe" {
		user := User{
			ID:    "jdoe",
			Name:  "John Smith",
			Email: "john.smith@example.com",
			Role:  "admin",
			Phone: "+1-555-0100",
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "https://mysrv.local:8444")

		json.NewEncoder(w).Encode(user)
		return
	}

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("User not found"))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users/{id}", handleUserInfo)

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
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
