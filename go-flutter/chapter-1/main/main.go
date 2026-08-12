/*

Chapter-1: Introduction to Web Authentication
Ultimate Web Authentication Handbook by Sambit Kumar Dash

This sample code helps you understand HTTP handlers and simple authentication methods.

Launch the application with the command:
go run ./main.go

The website runs at http://localhost:8080.

The website exposes the following endpoints:

/hello - it responds with a "Hello, World" message to the screen.
/count - it shows the importance of cookies. Every time you visit this endpoint, it
     reports how many times you visited the URL.
/session - implements the counter using a session cookie. The session cookie makes
     the counter transparent to the client.
/basicauth - implements the basic authentication scheme of HTTP. You can use jdoe as
     the username and password as the password to authenticate.
/resource - when you try to access this URL, it redirects to the /login URL and
     presents a form. You can provide jdoe as the username and password as the password
     to authenticate. The scheme utilizes the session cookie to maintain
     post-authentication sessions.
/transfer - this endpoint is vulnerable to CSRF attack. It allows you to transfer
     some amount to another account. It checks for the session cookie but does not
     implement any CSRF protection mechanism.
/transfer-safe - this endpoint is protected against CSRF attack. It implements a
     CSRF token mechanism to protect against CSRF attack.
*/

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	uuid "github.com/google/uuid"
)

func addHelloHandler(handlerMux *http.ServeMux) {
	handlerMux.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello, World!\n")
	})
}

func addCountHandler(handlerMux *http.ServeMux) {
	handlerMux.HandleFunc("/count", func(w http.ResponseWriter, req *http.Request) {
		count := 0
		if c, err := req.Cookie("count"); err == nil {
			if count, err = strconv.Atoi(c.Value); err != nil {
				log.Default().Print(err)
				count = 0
			}
		}
		count += 1

		http.SetCookie(w, &http.Cookie{
			Name:  "count",
			Value: strconv.Itoa(count),
		})

		str := fmt.Sprintf("You have visited: %d times.", count)
		log.Default().Print(str)

		io.WriteString(w, str)
	})
}

func addSessionHandler(handlerMux *http.ServeMux) {
	cmap := map[string]int{}
	handlerMux.HandleFunc("/session", func(w http.ResponseWriter, req *http.Request) {
		uid := ""
		if cookie, err := req.Cookie("session"); err != nil {
			uid = uuid.NewString()
			log.Default().Printf("No session found. Creating a new session: %s", uid)
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: uid,
			})
			cmap[uid] = 0
		} else {
			uid = cookie.Value
		}

		cmap[uid] += 1

		str := fmt.Sprintf("You have visited: %d times.", cmap[uid])
		log.Default().Print(str)

		io.WriteString(w, str)
	})
}

func addBasicAuthHandler(handlerMux *http.ServeMux) {
	pmap := map[string]string{"jdoe": "password"}
	handlerMux.HandleFunc("/basicauth", func(w http.ResponseWriter, req *http.Request) {
		if u, p, ok := req.BasicAuth(); ok {
			if pmap[u] == p {
				str := fmt.Sprintf("User %s authenticated.", u)
				io.WriteString(w, str)
				log.Default().Print(str)
			} else {
				str := fmt.Sprintf("User %s failed to authenticate.", u)
				w.WriteHeader(http.StatusUnauthorized)
				log.Default().Print(str)
			}
		} else {
			w.Header().Add("WWW-Authenticate", "Basic Realm=\"Access Server\"")
			w.WriteHeader(http.StatusUnauthorized)
			log.Default().Print("Basic authentication needed.")
		}
	})
}

func addFormBasedAuthHandler(handlerMux *http.ServeMux) {
	smap := map[string]string{}
	pmap := map[string]string{"jdoe": "password"}

	handlerMux.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) {
		form := `<form method="GET" enctype="application/x-www-form-urlencoded">
              <label for="user">Username:</label><br>
              <input type="text" id="user" name="user"><br>
              <label for="password">Password:</label><br>
              <input type="text" id="password" name="password">
              <input type="submit" value="Submit">
            </form>`
		user := req.FormValue("user")
		pass := req.FormValue("password")
		if user == "" || pass == "" {
			w.Header().Add("Content-Type", "text/html")
			w.Write([]byte(form))
		} else {
			if pmap[user] == pass {
				str := fmt.Sprintf("User %s authenticated.", user)
				log.Default().Print(str)
				uid := uuid.NewString()
				log.Default().Printf("No session found. Creating a new session: %s", uid)
				http.SetCookie(w, &http.Cookie{
					Name:  "session",
					Value: uid,
				})
				smap[uid] = user
				w.Header().Add("Location", "/resource")
				w.WriteHeader(http.StatusFound)
			} else {
				str := fmt.Sprintf("User %s failed to authenticate.", user)
				log.Default().Print(str)
				w.Header().Add("Content-Type", "text/html")
				w.Write([]byte(form))
			}
		}
	})

	handlerMux.HandleFunc("/resource", func(w http.ResponseWriter, req *http.Request) {
		if cookie, err := req.Cookie("session"); err != nil {
			w.Header().Add("Location", "/login")
			w.WriteHeader(http.StatusFound)
		} else {
			uid := cookie.Value
			user := smap[uid]
			if user != "" {
				str := fmt.Sprintf("User %s authenticated.", user)
				log.Default().Printf("Session %s found. Allowing user %s to access", uid, user)
				io.WriteString(w, str)
			} else {
				w.Header().Add("Location", "/login")
				w.WriteHeader(http.StatusFound)
			}
		}
	})
}

func addCSRFVulnerableHandler(handlerMux *http.ServeMux) {
	handlerMux.HandleFunc("/transfer", func(w http.ResponseWriter, req *http.Request) {
		// Check session validity
		if _, err := req.Cookie("session"); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		form := `<form method="POST" action="/transfer">
  <label for="amount">Amount:</label><br>
  <input type="text" id="amount" name="amount"><br>
  <input type="submit" value="Transfer">
  </form>`

		if req.Method == http.MethodGet {
			w.Header().Add("Content-Type", "text/html")
			w.Write([]byte(form))
			return
		}

		if req.Method == http.MethodPost {
			amount := req.FormValue("amount")
			str := fmt.Sprintf("Transferred %s units", amount)
			log.Default().Print(str)
			io.WriteString(w, str)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})
}

func addCSRFSafeHandler(handlerMux *http.ServeMux) {
	csrfTokens := map[string]string{}
	handlerMux.HandleFunc("/transfer-safe", func(w http.ResponseWriter, req *http.Request) {
		// Check session validity
		var cookie *http.Cookie
		var err error
		if cookie, err = req.Cookie("session"); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		sessionID := cookie.Value
		if sessionID == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if req.Method == http.MethodGet {
			csrfToken := uuid.NewString()
			csrfTokens[sessionID] = csrfToken
			form := fmt.Sprintf(`<form method="POST" action="/transfer-safe">
  <label for="amount">Amount:</label><br>
  <input type="text" id="amount" name="amount"><br>
  <input type="hidden" name="csrf_token" value="%s">
  <input type="submit" value="Transfer">
  </form>`, csrfToken)
			w.Header().Add("Content-Type", "text/html")
			w.Write([]byte(form))
			return
		}

		if req.Method == http.MethodPost {
			providedToken := req.FormValue("csrf_token")
			storedToken := csrfTokens[sessionID]
			if providedToken == "" || providedToken != storedToken {
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, "CSRF token validation failed")
				return
			}

			amount := req.FormValue("amount")
			str := fmt.Sprintf("Transferred %s units", amount)
			log.Default().Print(str)
			delete(csrfTokens, sessionID)
			io.WriteString(w, str)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})
}

func main() {
	handlerMux := http.NewServeMux()
	if handlerMux == nil {
		log.Fatal("Failed to create handler mux")
	}
	addHelloHandler(handlerMux)
	addCountHandler(handlerMux)
	addSessionHandler(handlerMux)
	addBasicAuthHandler(handlerMux)
	addFormBasedAuthHandler(handlerMux)
	addCSRFVulnerableHandler(handlerMux)
	addCSRFSafeHandler(handlerMux)
	server := &http.Server{
		Addr:    ":8080",
		Handler: handlerMux,
	}
	fmt.Println("Server running on :8080")
	log.Default().Fatal(server.ListenAndServe())
}
