package client

import (
	"fmt"
	"github.com/KrakenTech-LLC/gokrb5/v8/iana/flags"
	"github.com/KrakenTech-LLC/gokrb5/v8/iana/nametype"
	"github.com/KrakenTech-LLC/gokrb5/v8/krberror"
	"github.com/KrakenTech-LLC/gokrb5/v8/messages"
	"github.com/KrakenTech-LLC/gokrb5/v8/types"
	"strings"
)

// TGSREQGenerateAndExchange generates the TGS_REQ and performs a TGS exchange to retrieve a ticket to the specified SPN.
func (cl *Client) TGSREQGenerateAndExchange(spn types.PrincipalName, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, renewal bool) (tgsReq messages.TGSReq, tgsRep messages.TGSRep, err error) {
	tgsReq, err = messages.NewTGSReq(cl.Credentials.CName(), kdcRealm, cl.Config, tgt, sessionKey, spn, renewal)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: failed to generate a new TGS_REQ")
	}
	return cl.TGSExchange(tgsReq, kdcRealm, tgsRep.Ticket, sessionKey, 0)
}

// TGSExchange exchanges the provided TGS_REQ with the KDC to retrieve a TGS_REP.
// Referrals are automatically handled.
// The client's cache is updated with the ticket received.
func (cl *Client) TGSExchange(tgsReq messages.TGSReq, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, referral int) (messages.TGSReq, messages.TGSRep, error) {
	var tgsRep messages.TGSRep
	b, err := tgsReq.Marshal()
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to marshal TGS_REQ")
	}
	r, err := cl.sendToKDC(b, kdcRealm)
	if err != nil {
		if _, ok := err.(messages.KRBError); ok {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.KDCError, "TGS Exchange Error: kerberos error response from KDC when requesting for %s", tgsReq.ReqBody.SName.PrincipalNameString())
		}
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.NetworkingError, "TGS Exchange Error: issue sending TGS_REQ to KDC")
	}
	err = tgsRep.Unmarshal(r)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to process the TGS_REP")
	}
	err = tgsRep.DecryptEncPart(sessionKey)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to process the TGS_REP")
	}
	if ok, err := tgsRep.Verify(cl.Config, tgsReq); !ok {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: TGS_REP is not valid")
	}

	if tgsRep.Ticket.SName.NameString[0] == "krbtgt" && !tgsRep.Ticket.SName.Equal(tgsReq.ReqBody.SName) {
		if referral > 5 {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: maximum number of referrals exceeded")
		}
		// Server referral https://tools.ietf.org/html/rfc6806.html#section-8
		// The TGS Rep contains a TGT for another domain as the service resides in that domain.
		cl.addSession(tgsRep.Ticket, tgsRep.DecryptedEncPart)
		realm := tgsRep.Ticket.SName.NameString[len(tgsRep.Ticket.SName.NameString)-1]
		referral++
		if types.IsFlagSet(&tgsReq.ReqBody.KDCOptions, flags.EncTktInSkey) && len(tgsReq.ReqBody.AdditionalTickets) > 0 {
			tgsReq, err = messages.NewUser2UserTGSReq(cl.Credentials.CName(), kdcRealm, cl.Config, tgt, sessionKey, tgsReq.ReqBody.SName, tgsReq.Renewal, tgsReq.ReqBody.AdditionalTickets[0])
			if err != nil {
				return tgsReq, tgsRep, err
			}
		}
		tgsReq, err = messages.NewTGSReq(cl.Credentials.CName(), realm, cl.Config, tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, tgsReq.ReqBody.SName, tgsReq.Renewal)
		if err != nil {
			return tgsReq, tgsRep, err
		}
		return cl.TGSExchange(tgsReq, realm, tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, referral)
	}
	cl.cache.addEntry(
		tgsRep.Ticket,
		tgsRep.DecryptedEncPart.AuthTime,
		tgsRep.DecryptedEncPart.StartTime,
		tgsRep.DecryptedEncPart.EndTime,
		tgsRep.DecryptedEncPart.RenewTill,
		tgsRep.DecryptedEncPart.Key,
		tgsRep.DecryptedEncPart.Flags,
	)
	cl.Log("ticket added to cache for %s (EndTime: %v)", tgsRep.Ticket.SName.PrincipalNameString(), tgsRep.DecryptedEncPart.EndTime)
	return tgsReq, tgsRep, err
}

// GetServiceTicket makes a request to get a service ticket for the SPN specified
// SPN format: <SERVICE>/<FQDN> Eg. HTTP/www.example.com
// The ticket will be added to the client's ticket cache
func (cl *Client) GetServiceTicket(spn string) (messages.Ticket, types.EncryptionKey, error) {
	return cl.GetServiceTicketExt(spn, "")
}

// GetServiceTicket makes a request to get a service ticket for the SPN specified
// SPN format: <SERVICE>/<FQDN> Eg. HTTP/www.example.com
// The ticket will be added to the client's ticket cache

func (cl *Client) GetServiceTicketExt(spn, dcDomain string) (messages.Ticket, types.EncryptionKey, error) {
	var tkt messages.Ticket
	var skey types.EncryptionKey
	if tkt, skey, ok := cl.GetCachedTicket(spn); ok {
		// Already a valid ticket in the cache
		return tkt, skey, nil
	}
	parts := strings.Split(spn, "/")
	// Should perhaps support SPNs of the format <service class>/<host>:<port>/<service name>
	if len(parts) != 2 {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("Invalid SPN")
	}
	// Check if cross realm
	var realm string
	if strings.ToLower(parts[0]) == "krbtgt" {
		realm = strings.ToUpper(parts[1])
	} else if strings.Contains(parts[1], ".") {
		// Strip away host name if it is a FQDN
		parts = strings.SplitN(parts[1], ".", 2)
		realm = strings.ToUpper(parts[1])
	}
	// Handle a more advanced scenario where a referral ticket is required for communication
	// with another kerberos realm/domain
	if dcDomain != "" && !strings.EqualFold(cl.Credentials.Realm(), dcDomain) {
		// If client realm is not same as DC Realm we should look for a referral ticket and not for a TGT
		realm = dcDomain
	}

	spnNameType := nametype.KRB_NT_PRINCIPAL
	if strings.Contains(spn, "/") {
		spnNameType = nametype.KRB_NT_SRV_INST
	}
	princ := types.NewPrincipalName(spnNameType, spn)
	if realm == "" {
		realm = cl.spnRealm(princ)
	}

	// if we don't know the SPN's realm, ask the client realm's KDC
	if realm == "" {
		realm = cl.Credentials.Realm()
	}

	tgt, skey, err := cl.sessionTGT(realm)
	if err != nil {
		return tkt, skey, err
	}
	if tgt.SName.Equal(princ) {
		// Found our ticket already!
		return tgt, skey, nil
	}
	_, tgsRep, err := cl.TGSREQGenerateAndExchange(princ, realm, tgt, skey, false)
	if err != nil {
		return tkt, skey, err
	}
	return tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, nil
}
