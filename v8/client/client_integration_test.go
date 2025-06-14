package client_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"testing"
	"time"

	"fmt"
	"github.com/KrakenTech-LLC/gokrb5/v8/client"
	"github.com/KrakenTech-LLC/gokrb5/v8/config"
	"github.com/KrakenTech-LLC/gokrb5/v8/credentials"
	"github.com/KrakenTech-LLC/gokrb5/v8/iana/etypeID"
	"github.com/KrakenTech-LLC/gokrb5/v8/keytab"
	"github.com/KrakenTech-LLC/gokrb5/v8/spnego"
	"github.com/KrakenTech-LLC/gokrb5/v8/test"
	"github.com/KrakenTech-LLC/gokrb5/v8/test/testdata"
	"github.com/stretchr/testify/assert"
	"strings"
	"sync"
)

func TestClient_SuccessfulLogin_Keytab(t *testing.T) {
	test.Integration(t)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	var tests = []string{
		testdata.KDC_PORT_TEST_GOKRB5,
		testdata.KDC_PORT_TEST_GOKRB5_OLD,
		testdata.KDC_PORT_TEST_GOKRB5_LASTEST,
	}
	for _, tst := range tests {
		c.Realms[0].KDC = []string{addr + ":" + tst}
		cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

		err := cl.Login()
		if err != nil {
			t.Errorf("error on logging in with KDC %s: %v\n", tst, err)
		}
	}
}

func TestClient_SuccessfulLogin_Password(t *testing.T) {
	test.Integration(t)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	var tests = []string{
		testdata.KDC_PORT_TEST_GOKRB5,
		testdata.KDC_PORT_TEST_GOKRB5_OLD,
		testdata.KDC_PORT_TEST_GOKRB5_LASTEST,
	}
	for _, tst := range tests {
		c.Realms[0].KDC = []string{addr + ":" + tst}
		cl := client.NewWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue", c)

		err := cl.Login()
		if err != nil {
			t.Errorf("error on logging in with KDC %s: %v\n", tst, err)
		}
	}
}

func TestClient_SuccessfulLogin_TCPOnly(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	c.LibDefaults.UDPPreferenceLimit = 1
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
}

func TestClient_ASExchange_TGSExchange_EncTypes_Keytab(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_LASTEST}
	var tests = []string{
		"des3-cbc-sha1-kd",
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha256-128",
		"aes256-cts-hmac-sha384-192",
		"rc4-hmac",
	}
	for _, tst := range tests {
		c.LibDefaults.DefaultTktEnctypes = []string{tst}
		c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName[tst]}
		c.LibDefaults.DefaultTGSEnctypes = []string{tst}
		c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName[tst]}
		cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

		err := cl.Login()
		if err != nil {
			t.Errorf("error on login using enctype %s: %v\n", tst, err)
		}
		tkt, key, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
		if err != nil {
			t.Errorf("error in TGS exchange using enctype %s: %v", tst, err)
		}
		assert.Equal(t, "TEST.GOKRB5", tkt.Realm, "Realm in ticket not as expected for %s test", tst)
		assert.Equal(t, etypeID.ETypesByName[tst], key.KeyType, "Key is not for enctype %s", tst)
	}
}

func TestClient_ASExchange_TGSExchange_EncTypes_Password(t *testing.T) {
	test.Integration(t)

	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_LASTEST}
	var tests = []string{
		"des3-cbc-sha1-kd",
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha256-128",
		"aes256-cts-hmac-sha384-192",
		"rc4-hmac",
	}
	for _, tst := range tests {
		c.LibDefaults.DefaultTktEnctypes = []string{tst}
		c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName[tst]}
		c.LibDefaults.DefaultTGSEnctypes = []string{tst}
		c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName[tst]}
		cl := client.NewWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue", c)

		err := cl.Login()
		if err != nil {
			t.Errorf("error on login using enctype %s: %v\n", tst, err)
		}
		tkt, key, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
		if err != nil {
			t.Errorf("error in TGS exchange using enctype %s: %v", tst, err)
		}
		assert.Equal(t, "TEST.GOKRB5", tkt.Realm, "Realm in ticket not as expected for %s test", tst)
		assert.Equal(t, etypeID.ETypesByName[tst], key.KeyType, "Key is not for enctype %s", tst)
	}
}

func TestClient_FailedLogin(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5_WRONGPASSWD)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err == nil {
		t.Fatal("login with incorrect password did not error")
	}
}

func TestClient_SuccessfulLogin_UserRequiringPreAuth(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER2_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser2", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
}

func TestClient_SuccessfulLogin_UserRequiringPreAuth_TCPOnly(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER2_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	c.LibDefaults.UDPPreferenceLimit = 1
	cl := client.NewWithKeytab("testuser2", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
}

func TestClient_NetworkTimeout(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	c.Realms[0].KDC = []string{testdata.KDC_IP_TEST_GOKRB5_BADADDR + ":88"}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err == nil {
		t.Fatal("login with incorrect KDC address did not error")
	}
}

func TestClient_NetworkTryNextKDC(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	// Two out fo three times this should fail the first time.
	// So will run login twice to expect at least once the first time it will be to a bad KDC
	c.Realms[0].KDC = []string{testdata.KDC_IP_TEST_GOKRB5_BADADDR + ":88",
		testdata.KDC_IP_TEST_GOKRB5_BADADDR + ":88",
		addr + ":" + testdata.KDC_PORT_TEST_GOKRB5,
	}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatal("login failed")
	}
	err = cl.Login()
	if err != nil {
		t.Fatal("login failed")
	}
}

func TestClient_GetServiceTicket(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)

	//Check cache use - should get the same values back again
	tkt2, key2, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, tkt.EncPart.Cipher, tkt2.EncPart.Cipher)
	assert.Equal(t, key.KeyValue, key2.KeyValue)
}

func TestClient_GetServiceTicket_CanonicalizeTrue(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	c.LibDefaults.Canonicalize = true
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)

	//Check cache use - should get the same values back again
	tkt2, key2, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, tkt.EncPart.Cipher, tkt2.EncPart.Cipher)
	assert.Equal(t, key.KeyValue, key2.KeyValue)
}

func TestClient_GetServiceTicket_InvalidSPN(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "host.test.gokrb5"
	_, _, err = cl.GetServiceTicket(spn)
	assert.NotNil(t, err, "Expected unknown principal error")
	assert.True(t, strings.Contains(err.Error(), "KDC_ERR_S_PRINCIPAL_UNKNOWN"), "Error text not as expected")
}

func TestClient_GetServiceTicket_OlderKDC(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_OLD}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)
}

func TestMultiThreadedClientUse(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	var wg sync.WaitGroup
	wg.Add(5)
	for i := 0; i < 5; i++ {
		go func() {
			defer wg.Done()
			err := cl.Login()
			if err != nil {
				panic(err)
			}
		}()
	}
	wg.Wait()

	var wg2 sync.WaitGroup
	wg2.Add(5)
	for i := 0; i < 5; i++ {
		go func() {
			defer wg2.Done()
			err := spnegoGet(cl)
			if err != nil {
				panic(err)
			}
		}()
	}
	wg2.Wait()
}

func spnegoGet(cl *client.Client) error {
	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url+"/modgssapi/index.html", nil)
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		return fmt.Errorf("request error: %v\n", err)
	}
	if httpResp.StatusCode != http.StatusUnauthorized {
		return errors.New("did not get unauthorized code when no SPNEGO header set")
	}
	err = spnego.SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5")
	if err != nil {
		return fmt.Errorf("error setting client SPNEGO header: %v", err)
	}
	httpResp, err = http.DefaultClient.Do(r)
	if err != nil {
		return fmt.Errorf("request error: %v\n", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return errors.New("did not get OK code when SPNEGO header set")
	}
	return nil
}

func TestNewFromCCache(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatalf("error decoding test data")
	}
	cc := new(credentials.CCache)
	err = cc.Unmarshal(b)
	if err != nil {
		t.Fatal("error getting test CCache")
	}
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl, err := client.NewFromCCache(cc, c)
	if err != nil {
		t.Fatalf("error creating client from CCache: %v", err)
	}
	if ok, err := cl.IsConfigured(); !ok {
		t.Fatalf("client was not configured from CCache: %v", err)
	}
}

// Login to the TEST.GOKRB5 domain and request service ticket for resource in the RESDOM.GOKRB5 domain.
// There is a trust between the two domains.
func TestClient_GetServiceTicket_Trusted_Resource_Domain(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	for i, r := range c.Realms {
		if r.Realm == "TEST.GOKRB5" {
			c.Realms[i].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
		}
		if r.Realm == "RESDOM.GOKRB5" {
			c.Realms[i].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_RESDOM}
		}
	}

	c.LibDefaults.DefaultRealm = "TEST.GOKRB5"
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	c.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]}
	c.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]}

	err := cl.Login()

	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "HTTP/host.resdom.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"], key.KeyType)

	b, _ = hex.DecodeString(testdata.KEYTAB_SYSHTTP_RESDOM_GOKRB5)
	skt := keytab.New()
	skt.Unmarshal(b)
	err = tkt.DecryptEncPart(skt, nil)
	if err != nil {
		t.Errorf("error decrypting ticket with service keytab: %v", err)
	}
}

const (
	kinitCmd = "kinit"
	kvnoCmd  = "kvno"
	spn      = "HTTP/host.test.gokrb5"
)

func login() error {
	file, err := os.Create("/etc/krb5.conf")
	if err != nil {
		return fmt.Errorf("cannot open krb5.conf: %v", err)
	}
	defer file.Close()
	fmt.Fprintf(file, testdata.KRB5_CONF)

	cmd := exec.Command(kinitCmd, "testuser1@TEST.GOKRB5")

	stdinR, stdinW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	cmd.Stdin = stdinR
	cmd.Stderr = stderrW

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("could not start %s command: %v", kinitCmd, err)
	}

	go func() {
		io.WriteString(stdinW, "passwordvalue")
		stdinW.Close()
	}()
	errBuf := new(bytes.Buffer)
	go func() {
		io.Copy(errBuf, stderrR)
		stderrR.Close()
	}()

	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("%s did not run successfully: %v stderr: %s", kinitCmd, err, string(errBuf.Bytes()))
	}
	return nil
}

func getServiceTkt() error {
	cmd := exec.Command(kvnoCmd, spn)
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("could not start %s command: %v", kvnoCmd, err)
	}
	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("%s did not run successfully: %v", kvnoCmd, err)
	}
	return nil
}

func loadCCache() (*credentials.CCache, error) {
	usr, _ := user.Current()
	cpath := "/tmp/krb5cc_" + usr.Uid
	return credentials.LoadCCache(cpath)
}

func TestGetServiceTicketFromCCacheTGT(t *testing.T) {
	test.Privileged(t)

	err := login()
	if err != nil {
		t.Fatalf("error logging in with kinit: %v", err)
	}
	c, err := loadCCache()
	if err != nil {
		t.Errorf("error loading CCache: %v", err)
	}
	cfg, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	cfg.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl, err := client.NewFromCCache(c, cfg)
	if err != nil {
		t.Fatalf("error generating client from ccache: %v", err)
	}
	spn := "HTTP/host.test.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)

	//Check cache use - should get the same values back again
	tkt2, key2, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, tkt.EncPart.Cipher, tkt2.EncPart.Cipher)
	assert.Equal(t, key.KeyValue, key2.KeyValue)

	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url+"/modgssapi/index.html", nil)
	err = spnego.SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client SPNEGO header: %v", err)
	}
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "status code in response to client SPNEGO request not as expected")
}

func TestGetServiceTicketFromCCacheWithoutKDC(t *testing.T) {
	test.Privileged(t)

	err := login()
	if err != nil {
		t.Fatalf("error logging in with kinit: %v", err)
	}
	err = getServiceTkt()
	if err != nil {
		t.Fatalf("error getting service ticket: %v", err)
	}
	c, err := loadCCache()
	if err != nil {
		t.Errorf("error loading CCache: %v", err)
	}
	cfg, _ := config.NewFromString("...")
	cl, err := client.NewFromCCache(c, cfg)
	if err != nil {
		t.Fatalf("error generating client from ccache: %v", err)
	}
	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url+"/modgssapi/index.html", nil)
	err = spnego.SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client SPNEGO header: %v", err)
	}
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "status code in response to client SPNEGO request not as expected")
}

func TestClient_ChangePasswd(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	c.Realms[0].KPasswdServer = []string{addr + ":464"}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	ok, err := cl.ChangePasswd("newpassword")
	if err != nil {
		t.Fatalf("error changing password: %v", err)
	}
	assert.True(t, ok, "password was not changed")

	cl = client.NewWithPassword("testuser1", "TEST.GOKRB5", "newpassword", c)
	ok, err = cl.ChangePasswd(testdata.TESTUSER_PASSWORD)
	if err != nil {
		t.Fatalf("error changing password: %v", err)
	}
	assert.True(t, ok, "password was not changed back")

	cl = client.NewWithPassword("testuser1", "TEST.GOKRB5", testdata.TESTUSER_PASSWORD, c)
	err = cl.Login()
	if err != nil {
		t.Fatalf("Could not log back in after reverting password: %v", err)
	}
}

func TestClient_Destroy(t *testing.T) {
	test.Integration(t)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_SHORTTICKETS}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "HTTP/host.test.gokrb5"
	_, _, err = cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	n := runtime.NumGoroutine()
	time.Sleep(time.Second * 60)
	cl.Destroy()
	time.Sleep(time.Second * 5)
	assert.True(t, runtime.NumGoroutine() < n, "auto-renewal goroutine was not stopped when client destroyed")
	is, _ := cl.IsConfigured()
	assert.False(t, is, "client is still configured after it was destroyed")
}
