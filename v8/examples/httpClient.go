//go:build examples
// +build examples

package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/KrakenTech-LLC/gokrb5/v8/client"
	"github.com/KrakenTech-LLC/gokrb5/v8/config"
	"github.com/KrakenTech-LLC/gokrb5/v8/keytab"
	"github.com/KrakenTech-LLC/gokrb5/v8/spnego"
	"github.com/KrakenTech-LLC/gokrb5/v8/test/testdata"
)

const (
	port     = ":9080"
	kRB5CONF = `[libdefaults]
  default_realm = TEST.GOKRB5
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96

[realms]
 TEST.GOKRB5 = {
  kdc = 127.0.0.1:88
  admin_server = 127.0.0.1:749
  default_domain = test.gokrb5
 }

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
 `
)

func main() {
	l := log.New(os.Stderr, "GOKRB5 Client: ", log.LstdFlags)

	//defer profile.Start(profile.TraceProfile).Stop()
	// Load the keytab
	kb, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER2_TEST_GOKRB5)
	kt := keytab.New()
	err := kt.Unmarshal(kb)
	if err != nil {
		l.Fatalf("could not load client keytab: %v", err)
	}

	// Load the client krb5 config
	conf, err := config.NewFromString(kRB5CONF)
	if err != nil {
		l.Fatalf("could not load krb5.conf: %v", err)
	}
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr != "" {
		conf.Realms[0].KDC = []string{addr + ":88"}
	}

	// Create the client with the keytab
	cl := client.NewWithKeytab("testuser2", "TEST.GOKRB5", kt, conf, client.Logger(l), client.DisablePAFXFAST(true))

	// Log in the client
	err = cl.Login()
	if err != nil {
		l.Fatalf("could not login client: %v", err)
	}

	// Form the request
	url := "http://localhost" + port
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		l.Fatalf("could create request: %v", err)
	}

	spnegoCl := spnego.NewClient(cl, nil, "HTTP/host.test.gokrb5")

	// Make the request
	resp, err := spnegoCl.Do(r)
	if err != nil {
		l.Fatalf("error making request: %v", err)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		l.Fatalf("error reading response body: %v", err)
	}
	fmt.Println(string(b))
}
