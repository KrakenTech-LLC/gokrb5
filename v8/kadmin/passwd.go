// Package kadmin provides Kerberos administration capabilities.
package kadmin

import (
	"github.com/KrakenTech-LLC/gokrb5/v8/crypto"
	"github.com/KrakenTech-LLC/gokrb5/v8/krberror"
	"github.com/KrakenTech-LLC/gokrb5/v8/messages"
	"github.com/KrakenTech-LLC/gokrb5/v8/types"
)

// ChangePasswdMsg generates a Set Password request (RFC 3244, version 0xff80)
// using the ChangePasswdData ASN.1 structure with TargName and TargRealm.
// Also returns the subkey needed to decrypt the reply.
func ChangePasswdMsg(cname types.PrincipalName, realm, password string, tkt messages.Ticket, sessionKey types.EncryptionKey) (r Request, k types.EncryptionKey, err error) {
	// Create change password data struct and marshal to bytes
	chgpasswd := ChangePasswdData{
		NewPasswd: []byte(password),
		TargName:  cname,
		TargRealm: realm,
	}
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

// ChangeOwnPasswdMsg generates a Change Password request (RFC 2222, version 0x0001)
// using a simple password payload (raw new password bytes in KRB-PRIV UserData).
// This is the "change own password" variant — the KDC treats this as a self-service
// password change, which doesn't require "Reset Password" rights on the target object.
func ChangeOwnPasswdMsg(newPassword string, tkt messages.Ticket, sessionKey types.EncryptionKey) (r Request, k types.EncryptionKey, err error) {
	// Generate authenticator — use empty cname; the identity comes from the ticket
	auth, err := types.NewAuthenticator(tkt.Realm, tkt.SName)
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

	// RFC 2222: UserData is just the new password in UTF-8
	kp := messages.EncKrbPrivPart{
		UserData:       []byte(newPassword),
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
		Version: 1, // RFC 2222 version = 0x0001
	}
	return
}
