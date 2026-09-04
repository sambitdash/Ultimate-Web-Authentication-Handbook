/*
Chapter-9: WebAuthn Authentication
Ultimate Web Authentication Handbook by Sambit Kumar Dash

This sample code shows the WebAuthn registration and validation workflows.

# Add these values to the /etc/hosts file.
# On Windows, the file can be: C:\Windows\System32\drivers\etc\hosts
127.0.0.5 mysrv.local

Import the certs/sroot.crt root certificate into your browser's trusted roots
before accessing the website.

Go to the frontend folder and build the Flutter application using:

flutter build web

Start the server with the command:
go run ./webauthn.go

The website runs at https://mysrv.local:8443/

The server exposes the following endpoints:

/register/begin
/register/finish

These endpoints are used for registering a FIDO token over WebAuthn.

/login/begin
/login/finish

These endpoints are used for authenticating with the WebAuthn token.

The UI shows two views for registration and authentication.

*/

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"howa.in/common"
)

type userImpl struct {
	_WebAuthnID          []byte
	_WebAuthnName        string
	_WebAuthnDisplayName string
	_WebAuthnCredentials []webauthn.Credential
}

func (u userImpl) WebAuthnID() []byte {
	return u._WebAuthnID
}

func (u userImpl) WebAuthnName() string {
	return u._WebAuthnName
}

func (u userImpl) WebAuthnDisplayName() string {
	return u._WebAuthnDisplayName
}

func (u userImpl) WebAuthnCredentials() []webauthn.Credential {
	return u._WebAuthnCredentials
}

func (u userImpl) WebAuthnIcon() string {
	return ""
}

func (u *userImpl) AddCredential(c *webauthn.Credential) {
	u._WebAuthnCredentials = append(u._WebAuthnCredentials, *c)
}

type DataStore struct {
	mu   sync.Mutex
	data map[string]interface{}
}

func (d *DataStore) FindUserByWebAuthnID(id []byte) webauthn.User {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, v := range d.data {
		u, ok := v.(webauthn.User)
		if !ok {
			continue
		}
		if bytes.Equal(u.WebAuthnID(), id) {
			return u
		}
	}
	return nil
}

func (d *DataStore) SaveUser(u webauthn.User) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data[u.WebAuthnName()] = u
}

func (d *DataStore) GetUser(username string) webauthn.User {
	d.mu.Lock()
	defer d.mu.Unlock()

	u, ok := d.data[username]
	if !ok {
		buf := make([]byte, 64)
		_, err := rand.Read(buf)
		if err != nil {
			return nil
		}
		usr := userImpl{
			_WebAuthnID:          buf,
			_WebAuthnName:        username,
			_WebAuthnDisplayName: username,
			_WebAuthnCredentials: make([]webauthn.Credential, 0),
		}
		d.data[username] = usr
		u = usr
	}
	v, ok := u.(webauthn.User)
	if !ok {
		return nil
	}
	return v
}

func (d *DataStore) SaveSession(state string, s *webauthn.SessionData) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data[state] = s
}

func (d *DataStore) GetSession(state string) *webauthn.SessionData {
	d.mu.Lock()
	defer d.mu.Unlock()
	val, ok := d.data[state]
	if !ok || val == nil {
		return nil
	}
	s, ok := val.(*webauthn.SessionData)
	if !ok {
		return nil
	}
	return s
}

func addWebAuthnHandlers(mux *http.ServeMux) {
	datastore := &DataStore{
		mu:   sync.Mutex{},
		data: make(map[string]interface{}),
	}

	wconfig := &webauthn.Config{
		RPDisplayName: "HOWA Webauthn",
		RPID:          "mysrv.local",
		RPOrigins:     []string{"https://mysrv.local:8443"},
	}

	wauthn, err := webauthn.New(wconfig)
	if err != nil {
		log.Fatal(err)
	}

	jsonResponse := func(w http.ResponseWriter, obj interface{}) {
		w.Header().Set("Content-Type", "application/json")
		jsonResp, _ := json.MarshalIndent(obj, "", "  ")
		w.Write(jsonResp)
	}

	mux.HandleFunc("/webauthn/register/begin", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		if username == "" {
			http.Error(w, "invalid username", http.StatusBadRequest)
			log.Print("invalid username")
			return
		}

		state := r.FormValue("state")
		if state == "" {
			http.Error(w, "invalid state", http.StatusBadRequest)
			log.Print("invalid state")
			return
		}

		user := datastore.GetUser(username)
		cred_creation, session, err := wauthn.BeginRegistration(
			user,
			webauthn.WithCredentialParameters(
				[]protocol.CredentialParameter{
					{
						Type:      protocol.PublicKeyCredentialType,
						Algorithm: webauthncose.AlgES256,
					},
					{
						Type:      protocol.PublicKeyCredentialType,
						Algorithm: webauthncose.AlgRS256,
					},
				},
			),
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				ResidentKey: protocol.ResidentKeyRequirementPreferred,
			}),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			log.Print(err.Error())
			return
		}
		options := &cred_creation.Response
		optionsJson, _ := json.MarshalIndent(options, "", "  ")
		optionsJson = append(optionsJson, byte('\n'))
		log.Writer().Write(optionsJson)

		datastore.SaveSession(state, session)
		jsonResponse(w, options)
		log.Printf("Sending registration information for user: %s state: %s", username, state)
	})

	mux.HandleFunc("/webauthn/register/finish", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		if username == "" {
			http.Error(w, "invalid username", http.StatusBadRequest)
			log.Print("invalid username")
			return
		}

		state := r.FormValue("state")
		if state == "" {
			http.Error(w, "invalid state", http.StatusBadRequest)
			log.Print("invalid state")
			return
		}

		ccr, err := protocol.ParseCredentialCreationResponse(r)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			perr := err.(*protocol.Error)
			log.Print(perr.Error(), ' ', perr.DevInfo)
			return
		}

		session := datastore.GetSession(state)

		if ccr.Response.CollectedClientData.Challenge != session.Challenge {
			http.Error(w, "Internal Server Error", http.StatusBadRequest)
			log.Print("invalid session or client")
			return
		}

		ccrRespJson, _ := json.MarshalIndent(ccr.Response, "", "  ")
		ccrRespJson = append(ccrRespJson, byte('\n'))
		log.Writer().Write(ccrRespJson)

		user := datastore.GetUser(username).(userImpl) // Get the user

		// Get the session data stored from the function above

		credential, err := wauthn.CreateCredential(user, *session, ccr)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Print(err)
			return
		}

		jsonResponse(w, &struct {
			Message string `json:"message"`
		}{Message: "Registration Success"})
		user.AddCredential(credential)
		datastore.SaveUser(user)

		log.Printf("User: %s registered a WebAuthn credential.", username)
	})

	mux.HandleFunc("/webauthn/login/begin", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		isDiscoveryLogin := username == "" || username == "null"

		var (
			cred_assertion *protocol.CredentialAssertion
			options        *protocol.PublicKeyCredentialRequestOptions
			session        *webauthn.SessionData
			err            error
		)

		if isDiscoveryLogin {
			cred_assertion, session, err = wauthn.BeginDiscoverableMediatedLogin(protocol.MediationConditional)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				log.Printf("discovery login error: %s", err.Error())
				return
			}
		} else {
			user := datastore.GetUser(username)
			cred_assertion, session, err = wauthn.BeginLogin(user)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				log.Printf("user: %s error: %s", username, err.Error())
				return
			}
		}

		state := r.FormValue("state")
		datastore.SaveSession(state, session)
		if isDiscoveryLogin {
			log.Printf("Sending login information for discovery login state: %s", state)
		} else {
			log.Printf("Sending login information for user: %s state: %s", username, state)
		}

		options = &cred_assertion.Response
		optionsJson, _ := json.MarshalIndent(options, "", "  ")
		optionsJson = append(optionsJson, byte('\n'))
		log.Writer().Write(optionsJson)

		jsonResponse(w, options)
	})

	mux.HandleFunc("/webauthn/login/finish", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")

		state := r.FormValue("state")
		if state == "" {
			http.Error(w, "invalid state", http.StatusBadRequest)
			log.Print("invalid state")
			return
		}

		cad, err := protocol.ParseCredentialRequestResponse(r)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			perr := err.(*protocol.Error)
			log.Print(perr.Error(), ' ', perr.DevInfo)
			return
		}

		var session *webauthn.SessionData
		session = datastore.GetSession(r.FormValue("state"))
		if cad.Response.CollectedClientData.Challenge != session.Challenge {
			http.Error(w, "Internal Server Error", http.StatusBadRequest)
			log.Print("invalid session or client")
			return
		}

		cadRespJson, _ := json.MarshalIndent(cad.Response, "", "  ")
		cadRespJson = append(cadRespJson, byte('\n'))
		log.Writer().Write(cadRespJson)

		var user userImpl
		var message string = ""
		if username != "" {
			user = datastore.GetUser(username).(userImpl) // Get the user
			_, err = wauthn.ValidateLogin(user, *session, cad)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				log.Print(err)
				return
			}
			message = "Authentication Successful for user: " + username
		} else {
			var u webauthn.User
			u, _, err = wauthn.ValidatePasskeyLogin(func(rawId, userHandle []byte) (webauthn.User, error) {
				log.Default().Printf("Looking up user by WebAuthn ID: %x", userHandle)
				user := datastore.FindUserByWebAuthnID(userHandle)
				return user, nil
			}, *session, cad)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				log.Print(err)
				return
			}
			user = u.(userImpl)
			username = user.WebAuthnName()
			message = "Authentication Successful for passkey user: " + username
		}
		// Get the session data stored from the function above
		jsonResponse(w, &struct {
			Message string `json:"message"`
		}{Message: message})
		log.Print(message)
	})
}

func main() {
	server, mux, err := common.SetupHTTPSServer(
		"mysrv.local", "8443",
		"../certs/scas.crt",
		"../certs/mysrv.local.crt",
		"../certs/mysrv.local.key",
		[]byte("password"),
	)
	if err != nil {
		log.Default().Fatal(err)
	}
	addWebAuthnHandlers(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("frontend/build/web")).ServeHTTP(w, r)
	})
	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
