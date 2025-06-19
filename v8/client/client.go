// Package client provides a client library and methods for Kerberos 5 authentication.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/KrakenTech-LLC/gokrb5/v8/config"
	"github.com/KrakenTech-LLC/gokrb5/v8/credentials"
	"github.com/KrakenTech-LLC/gokrb5/v8/crypto"
	"github.com/KrakenTech-LLC/gokrb5/v8/crypto/etype"
	"github.com/KrakenTech-LLC/gokrb5/v8/iana/errorcode"
	"github.com/KrakenTech-LLC/gokrb5/v8/iana/nametype"
	"github.com/KrakenTech-LLC/gokrb5/v8/keytab"
	"github.com/KrakenTech-LLC/gokrb5/v8/krberror"
	"github.com/KrakenTech-LLC/gokrb5/v8/messages"
	"github.com/KrakenTech-LLC/gokrb5/v8/types"
)

// Client side configuration and state.
type Client struct {
	Credentials *credentials.Credentials
	Config      *config.Config
	settings    *Settings
	sessions    *sessions
	cache       *Cache
}

// NewWithPassword creates a new client from a password credential.
// Set the realm to empty string to use the default realm from config.
func NewWithPassword(username, realm, password string, krb5conf *config.Config, settings ...func(*Settings)) *Client {
	creds := credentials.New(username, realm)
	return &Client{
		Credentials: creds.WithPassword(password),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
		},
		cache: NewCache(),
	}
}

// NewWithHash creates a new client from an NT Hash.
func NewWithHash(username, realm string, hash []byte, krb5conf *config.Config, settings ...func(*Settings)) *Client {
	creds := credentials.New(username, realm)
	c := &Client{
		Config:   krb5conf,
		settings: NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
		},
		cache: NewCache(),
	}
	if len(hash) == 16 {
		c.Credentials = creds.WithNTHash(hash)
	} else {
		fmt.Printf("Invalid Hash provided for new client\n")
		return nil
	}

	return c
}

// NewWithKey creates a new client from a user's AES Key 128/256 bit.
func NewWithKey(username, realm string, key []byte, krb5conf *config.Config, settings ...func(*Settings)) *Client {
	creds := credentials.New(username, realm)
	c := &Client{
		Config:   krb5conf,
		settings: NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
		},
		cache: NewCache(),
	}
	if len(key) != 16 && len(key) != 32 {
		fmt.Printf("Invalid AES key provided for new client\n")
		return nil
	} else {
		c.Credentials = creds.WithAESKey(key)
	}

	return c
}

// NewWithKeytab creates a new client from a keytab credential.
func NewWithKeytab(username, realm string, kt *keytab.Keytab, krb5conf *config.Config, settings ...func(*Settings)) *Client {
	creds := credentials.New(username, realm)
	return &Client{
		Credentials: creds.WithKeytab(kt),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
		},
		cache: NewCache(),
	}
}

// NewFromCCache create a client from a populated client cache.
//
// WARNING: A client created from CCache does not automatically renew TGTs and a failure will occur after the TGT expires.
func NewFromCCache(c *credentials.CCache, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	cl := &Client{
		Credentials: c.GetClientCredentials(),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
		},
		cache: NewCache(),
	}
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", c.DefaultPrincipal.Realm},
	}
	cred, ok := c.GetEntry(spn)
	if !ok {
		return cl, errors.New("TGT not found in CCache")
	}
	var tgt messages.Ticket
	err := tgt.Unmarshal(cred.Ticket)
	if err != nil {
		return cl, fmt.Errorf("TGT bytes in cache are not valid: %v", err)
	}
	cl.sessions.Entries[c.DefaultPrincipal.Realm] = &session{
		realm:      c.DefaultPrincipal.Realm,
		authTime:   cred.AuthTime,
		endTime:    cred.EndTime,
		renewTill:  cred.RenewTill,
		tgt:        tgt,
		sessionKey: cred.Key,
	}
	for _, cred := range c.GetEntries() {
		var tkt messages.Ticket
		err = tkt.Unmarshal(cred.Ticket)
		if err != nil {
			return cl, fmt.Errorf("cache entry ticket bytes are not valid: %v", err)
		}
		cl.cache.addEntry(
			tkt,
			cred.AuthTime,
			cred.StartTime,
			cred.EndTime,
			cred.RenewTill,
			cred.Key,
		)
	}
	return cl, nil
}

// Key returns the client's encryption key for the specified encryption type and its kvno (kvno of zero will find latest).
// The key can be retrieved either from the keytab or generated from the client's password.
// If the client has both a keytab and a password defined the keytab is favoured as the source for the key
// A KRBError can be passed in the event the KDC returns one of type KDC_ERR_PREAUTH_REQUIRED and is required to derive
// the key for pre-authentication from the client's password. If a KRBError is not available, pass nil to this argument.
func (cl *Client) Key(etype etype.EType, kvno int, krberr *messages.KRBError) (types.EncryptionKey, int, error) {
	if cl.Credentials.HasKeytab() && etype != nil {
		return cl.Credentials.Keytab().GetEncryptionKey(cl.Credentials.CName(), cl.Credentials.Domain(), kvno, etype.GetETypeID())
	} else if cl.Credentials.HasPassword() {
		if krberr != nil && krberr.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED {
			var pas types.PADataSequence
			err := pas.Unmarshal(krberr.EData)
			if err != nil {
				return types.EncryptionKey{}, 0, fmt.Errorf("could not get PAData from KRBError to generate key from password: %v", err)
			}
			key, _, err := crypto.GetKeyFromPassword(cl.Credentials.Password(), krberr.CName, krberr.CRealm, etype.GetETypeID(), pas)
			return key, 0, err
		}
		key, _, err := crypto.GetKeyFromPassword(cl.Credentials.Password(), cl.Credentials.CName(), cl.Credentials.Domain(), etype.GetETypeID(), types.PADataSequence{})
		return key, 0, err
	}
	return types.EncryptionKey{}, 0, errors.New("credential has neither keytab or password to generate key")
}

// IsConfigured indicates if the client has the values required set.
func (cl *Client) IsConfigured() (bool, error) {
	if cl.Credentials.UserName() == "" {
		return false, errors.New("client does not have a username")
	}
	if cl.Credentials.Domain() == "" {
		return false, errors.New("client does not have a define realm")
	}
	// Client needs to have either a password, keytab or a session already (later when loading from CCache)
	if !cl.Credentials.HasPassword() && !cl.Credentials.HasKeytab() {
		authTime, _, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
		if err != nil || authTime.IsZero() {
			return false, errors.New("client has neither a keytab nor a password set and no session")
		}
	}
	if !cl.Config.LibDefaults.DNSLookupKDC {
		for _, r := range cl.Config.Realms {
			if r.Realm == cl.Credentials.Domain() {
				if len(r.KDC) > 0 {
					return true, nil
				}
				return false, errors.New("client krb5 config does not have any defined KDCs for the default realm")
			}
		}
	}
	return true, nil
}

// Login the client with the KDC via an AS exchange.
func (cl *Client) Login() error {
	if ok, err := cl.IsConfigured(); !ok {
		return err
	}
	if !cl.Credentials.HasPassword() && !cl.Credentials.HasKeytab() {
		_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
		if err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "no user credentials available and error getting any existing session")
		}
		if time.Now().UTC().After(endTime) {
			return krberror.New(krberror.KRBMsgError, "cannot login, no user credentials available and no valid existing session")
		}
		// no credentials but there is a session with tgt already
		return nil
	}
	ASReq, err := messages.NewASReqForTGT(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "error generating new AS_REQ")
	}
	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return err
	}
	cl.addSession(ASRep.Ticket, ASRep.DecryptedEncPart)
	return nil
}

// AffirmLogin will only perform an AS exchange with the KDC if the client does not already have a TGT.
func (cl *Client) AffirmLogin() error {
	_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
	if err != nil || time.Now().UTC().After(endTime) {
		err := cl.Login()
		if err != nil {
			return fmt.Errorf("could not get valid TGT for client's realm: %v", err)
		}
	}
	return nil
}

// realmLogin obtains or renews a TGT and establishes a session for the realm specified.
func (cl *Client) realmLogin(realm string) error {
	if realm == cl.Credentials.Domain() {
		return cl.Login()
	}
	_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
	if err != nil || time.Now().UTC().After(endTime) {
		err := cl.Login()
		if err != nil {
			return fmt.Errorf("could not get valid TGT for client's realm: %v", err)
		}
	}
	tgt, skey, err := cl.sessionTGT(cl.Credentials.Domain())
	if err != nil {
		return err
	}

	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}

	_, tgsRep, err := cl.TGSREQGenerateAndExchange(spn, cl.Credentials.Domain(), tgt, skey, false)
	if err != nil {
		return err
	}
	cl.addSession(tgsRep.Ticket, tgsRep.DecryptedEncPart)

	return nil
}

// Destroy stops the auto-renewal of all sessions and removes the sessions and cache entries from the client.
func (cl *Client) Destroy() {
	creds := credentials.New("", "")
	cl.sessions.destroy()
	cl.cache.clear()
	cl.Credentials = creds
	cl.Log("client destroyed")
}

// Diagnostics runs a set of checks that the client is properly configured and writes details to the io.Writer provided.
func (cl *Client) Diagnostics(w io.Writer) error {
	cl.Print(w)
	var errs []string
	if cl.Credentials.HasKeytab() {
		var loginRealmEncTypes []int32
		for _, e := range cl.Credentials.Keytab().Entries {
			if e.Principal.Realm == cl.Credentials.Realm() {
				loginRealmEncTypes = append(loginRealmEncTypes, e.Key.KeyType)
			}
		}
		for _, et := range cl.Config.LibDefaults.DefaultTktEnctypeIDs {
			var etInKt bool
			for _, val := range loginRealmEncTypes {
				if val == et {
					etInKt = true
					break
				}
			}
			if !etInKt {
				errs = append(errs, fmt.Sprintf("default_tkt_enctypes specifies %d but this enctype is not available in the client's keytab", et))
			}
		}
		for _, et := range cl.Config.LibDefaults.PreferredPreauthTypes {
			var etInKt bool
			for _, val := range loginRealmEncTypes {
				if int(val) == et {
					etInKt = true
					break
				}
			}
			if !etInKt {
				errs = append(errs, fmt.Sprintf("preferred_preauth_types specifies %d but this enctype is not available in the client's keytab", et))
			}
		}
	}
	udpCnt, udpKDC, err := cl.Config.GetKDCs(cl.Credentials.Realm(), false)
	if err != nil {
		errs = append(errs, fmt.Sprintf("error when resolving KDCs for UDP communication: %v", err))
	}
	if udpCnt < 1 {
		errs = append(errs, "no KDCs resolved for communication via UDP.")
	} else {
		b, _ := json.MarshalIndent(&udpKDC, "", "  ")
		fmt.Fprintf(w, "UDP KDCs: %s\n", string(b))
	}
	tcpCnt, tcpKDC, err := cl.Config.GetKDCs(cl.Credentials.Realm(), false)
	if err != nil {
		errs = append(errs, fmt.Sprintf("error when resolving KDCs for TCP communication: %v", err))
	}
	if tcpCnt < 1 {
		errs = append(errs, "no KDCs resolved for communication via TCP.")
	} else {
		b, _ := json.MarshalIndent(&tcpKDC, "", "  ")
		fmt.Fprintf(w, "TCP KDCs: %s\n", string(b))
	}

	if errs == nil || len(errs) < 1 {
		return nil
	}
	err = fmt.Errorf(strings.Join(errs, "\n"))
	return err
}

// Print writes the details of the client to the io.Writer provided.
func (cl *Client) Print(w io.Writer) {
	c, _ := cl.Credentials.JSON()
	fmt.Fprintf(w, "Credentials:\n%s\n", c)

	s, _ := cl.sessions.JSON()
	fmt.Fprintf(w, "TGT Sessions:\n%s\n", s)

	c, _ = cl.cache.JSON()
	fmt.Fprintf(w, "Service ticket cache:\n%s\n", c)

	s, _ = cl.settings.JSON()
	fmt.Fprintf(w, "Settings:\n%s\n", s)

	j, _ := cl.Config.JSON()
	fmt.Fprintf(w, "Krb5 config:\n%s\n", j)

	k, _ := cl.Credentials.Keytab().JSON()
	fmt.Fprintf(w, "Keytab:\n%s\n", k)
}

// AddCacheEntries create populates an existing cache with new tickets
func (cl *Client) AddCacheEntries(c *credentials.CCache) error {
	var err error
	for _, cred := range c.GetEntries() {
		var tkt messages.Ticket
		err = tkt.Unmarshal(cred.Ticket)
		if err != nil {
			return fmt.Errorf("cache entry ticket bytes are not valid: %v", err)
		}
		cl.cache.addEntry(
			tkt,
			cred.AuthTime,
			cred.StartTime,
			cred.EndTime,
			cred.RenewTill,
			cred.Key,
			cred.TicketFlags,
		)
	}
	return nil
}

func (cl *Client) GetTGT(domain string) (tgt messages.Ticket, sessionKey types.EncryptionKey, err error) {
	return cl.sessionTGT(domain)
}

func (cl *Client) addTGTToCCache(cache *credentials.CCache, clientPrincipal types.PrincipalName, clientRealm string) (err error) {
	var flags asn1.BitString
	clientRealm = strings.ToUpper(clientRealm)
	if clientRealm == "" {
		clientRealm = cl.Credentials.Realm()
	}
	principal := credentials.NewPrincipal(clientPrincipal, clientRealm)
	var cAddr []types.HostAddress
	flags, cAddr, err = cl.sessionTGTDetails(clientRealm)
	if err != nil {
		return
	}
	var tgt messages.Ticket
	var sessionKey types.EncryptionKey
	tgt, sessionKey, err = cl.sessionTGT(clientRealm)
	if err != nil {
		return
	}
	var authTime, endTime, renewTime time.Time
	authTime, endTime, renewTime, _, err = cl.sessionTimes(clientRealm)
	if err != nil {
		return
	}
	var tgtBytes []byte
	kdcPrincipal := credentials.NewPrincipal(tgt.SName, tgt.Realm)
	tgtBytes, err = tgt.Marshal()
	if err != nil {
		return
	}
	credTGT := &credentials.Credential{
		Client:      principal,
		Server:      kdcPrincipal,
		Key:         sessionKey,
		AuthTime:    authTime,
		StartTime:   authTime,
		EndTime:     endTime,
		RenewTill:   renewTime,
		TicketFlags: flags,
		Addresses:   cAddr,
		Ticket:      tgtBytes,
	}
	cache.AddCredential(credTGT)
	return
}

func (cl *Client) SaveAllTicketsToCCache(ccache *credentials.CCache, clientPrincipal types.PrincipalName, clientRealm string) (err error) {
	err = cl.addTGTToCCache(ccache, clientPrincipal, clientRealm)
	if err != nil {
		fmt.Printf("Couldn't save session TGT for userDomain: %s because: %s\n", clientRealm, err.Error())
	}
	entries := cl.cache.getEntries()
	for _, entry := range entries {
		if entry.SPN == "krbtgt/"+cl.Credentials.Realm() {
			// skip
			continue
		}
		if ccache.Contains(entry.Ticket.SName) {
			// Skip since already in the ccache
			continue
		}
		var ticketBytes []byte
		server := credentials.NewPrincipal(entry.Ticket.SName, cl.Credentials.Realm())
		ticketBytes, err = entry.Ticket.Marshal()
		if err != nil {
			return
		}

		cred := &credentials.Credential{
			Client:      credentials.NewPrincipal(clientPrincipal, clientRealm),
			Server:      server,
			Key:         entry.SessionKey,
			AuthTime:    entry.AuthTime,
			StartTime:   entry.StartTime,
			EndTime:     entry.EndTime,
			RenewTill:   entry.RenewTill,
			TicketFlags: entry.Flags,
			Ticket:      ticketBytes,
		}
		ccache.AddCredential(cred)
	}
	return
}

func (cl *Client) SaveSPNToCCache(ccache *credentials.CCache, clientPrincipal types.PrincipalName, clientRealm, spn, altService string) (err error) {
	var ticketBytes []byte
	var cred *credentials.Credential
	principal := credentials.NewPrincipal(clientPrincipal, clientRealm)

	parts := strings.Split(spn, "/")
	if len(parts) != 2 {
		return fmt.Errorf("Invalid SPN!")
	}
	if strings.EqualFold(parts[0], "krbtgt") {
		var tgt messages.Ticket
		var sessionKey types.EncryptionKey
		var flags asn1.BitString
		var cAddr []types.HostAddress
		tgt, sessionKey, err = cl.GetTGT(parts[1])
		if err != nil {
			return err
		}
		flags, cAddr, err = cl.sessionTGTDetails(parts[1])
		if err != nil {
			return
		}
		var authTime, endTime, renewTime time.Time
		authTime, endTime, renewTime, _, err = cl.sessionTimes(cl.Credentials.Realm())
		if err != nil {
			return
		}
		var tgtBytes []byte
		kdcPrincipal := credentials.NewPrincipal(tgt.SName, tgt.Realm)
		tgtBytes, err = tgt.Marshal()
		if err != nil {
			return
		}

		cred = &credentials.Credential{
			Client:      principal,
			Server:      kdcPrincipal,
			Key:         sessionKey,
			AuthTime:    authTime,
			StartTime:   authTime,
			EndTime:     endTime,
			RenewTill:   renewTime,
			TicketFlags: flags,
			Addresses:   cAddr,
			Ticket:      tgtBytes,
		}
	} else {
		entry, found := cl.cache.getEntry(spn)
		if !found {
			err = fmt.Errorf("Service Ticket not found in cache with SPN: %s", spn)
			return
		}
		server := credentials.NewPrincipal(entry.Ticket.SName, entry.Ticket.Realm)
		if altService != "" {
			newSPN := ""
			if strings.Contains(altService, "/") {
				newSPN = altService
			} else {
				// Assume that the SPN is verified to be valid and contains a /
				newSPN = altService + "/" + parts[1]
			}
			// Replace Sname in ticket for spn
			server.PrincipalName = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, newSPN)
			entry.Ticket.SName = server.PrincipalName
		}

		ticketBytes, err = entry.Ticket.Marshal()
		if err != nil {
			return
		}
		cred = &credentials.Credential{
			Client:      principal,
			Server:      server,
			Key:         entry.SessionKey,
			AuthTime:    entry.AuthTime,
			StartTime:   entry.StartTime,
			EndTime:     entry.EndTime,
			RenewTill:   entry.RenewTill,
			TicketFlags: entry.Flags,
			Ticket:      ticketBytes,
		}
	}
	ccache.AddCredential(cred)
	return nil
}
