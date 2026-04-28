// Package kadmin provides Kerberos administration capabilities.
package kadmin

import (
	"github.com/KrakenTech-LLC/gokrb5/v8/crypto"
	"github.com/KrakenTech-LLC/gokrb5/v8/krberror"
	"github.com/KrakenTech-LLC/gokrb5/v8/messages"
	"github.com/KrakenTech-LLC/gokrb5/v8/types"
)

// ChangePasswdMsg generates a Set Password request (RFC 3244, version 0xff80)
// with TargName and TargRealm in the ChangePasswdData. This is an admin
// "set another user's password" operation — the KDC checks that the caller
// has "Reset Password" rights on the target object.
func ChangePasswdMsg(cname types.PrincipalName, realm, password string, tkt messages.Ticket, sessionKey types.EncryptionKey) (r Request, k types.EncryptionKey, err error) {
	chgpasswd := ChangePasswdData{
		NewPasswd: []byte(password),
		TargName:  cname,
		TargRealm: realm,
	}
	return buildChangePasswdRequest(cname, realm, chgpasswd, tkt, sessionKey)
}

// ChangeOwnPasswdMsg generates a Change Password request (RFC 3244, version 0xff80)
// WITHOUT TargName and TargRealm. Per RFC 3244 §2:
//
//	"If the TargName or the TargRealm field is missing, the change is for
//	 the authenticating user."
//
// This is the self-service "change own password" variant. The KDC does NOT
// require "Reset Password" rights — it only checks that the caller is changing
// their own password. Works for users and machine accounts alike.
func ChangeOwnPasswdMsg(newPassword string, cname types.PrincipalName, realm string, tkt messages.Ticket, sessionKey types.EncryptionKey) (r Request, k types.EncryptionKey, err error) {
	chgpasswd := ChangePasswdData{
		NewPasswd: []byte(newPassword),
		// TargName and TargRealm intentionally omitted — makes this a self-change
	}
	return buildChangePasswdRequest(cname, realm, chgpasswd, tkt, sessionKey)
}

// buildChangePasswdRequest is the shared implementation for building a kpasswd
// request message. Both ChangePasswdMsg and ChangeOwnPasswdMsg use this.
func buildChangePasswdRequest(cname types.PrincipalName, realm string, chgpasswd ChangePasswdData, tkt messages.Ticket, sessionKey types.EncryptionKey) (r Request, k types.EncryptionKey, err error) {
	chpwdb, err := chgpasswd.Marshal()
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error marshaling change passwd data")
		return
	}

	// Generate authenticator
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
		return
	}
	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating subkey etype")
		return
	}
	err = auth.GenerateSeqNumberAndSubKey(etype.GetETypeID(), etype.GetKeyByteSize())
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating subkey")
		return
	}
	k = auth.SubKey

	// Generate AP_REQ
	APreq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		return
	}

	// Form the KRBPriv encpart data
	kp := messages.EncKrbPrivPart{
		UserData:       chpwdb,
		Timestamp:      auth.CTime,
		Usec:           auth.Cusec,
		SequenceNumber: auth.SeqNumber,
	}
	kpriv := messages.NewKRBPriv(kp)
	err = kpriv.EncryptEncPart(k)
	if err != nil {
		err = krberror.Errorf(err, krberror.EncryptingError, "error encrypting change passwd data")
		return
	}

	r = Request{
		APREQ:   APreq,
		KRBPriv: kpriv,
	}
	return
}
