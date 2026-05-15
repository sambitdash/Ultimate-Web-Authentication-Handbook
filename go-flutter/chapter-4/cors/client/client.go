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
	w.Write([]byte(`<h1>User Info</h1>
<div id="tableContainer"></div>
<script>
fetch('https://idp.local:8443/users/jdoe')
  .then(response => response.json())
  .then(data => {
    const table = document.createElement('table');
    table.border = '1';
    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    Object.keys(data).forEach(key => {
      const th = document.createElement('th');
      th.textContent = key;
      headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    const dataRow = document.createElement('tr');
    Object.values(data).forEach(value => {
      const td = document.createElement('td');
      td.textContent = value;
      dataRow.appendChild(td);
    });
    tbody.appendChild(dataRow);
    table.appendChild(tbody);
    document.getElementById('tableContainer').appendChild(table);
  })
  .catch(error => console.error('Error:', error));
</script>`))
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
		ServerName:   "mysrv.local",
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*cert},
	}

	server := &http.Server{
		Addr:      ":8444",
		TLSConfig: tlsConfig,
	}

	log.Default().Fatal(server.ListenAndServeTLS("", ""))
}
