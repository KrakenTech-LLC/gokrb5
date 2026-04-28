package client

import (
	"fmt"

	"github.com/KrakenTech-LLC/gokrb5/v8/kadmin"
	"github.com/KrakenTech-LLC/gokrb5/v8/messages"
)

// Kpasswd server response codes.
const (
	KRB5_KPASSWD_SUCCESS             = 0
	KRB5_KPASSWD_MALFORMED           = 1
	KRB5_KPASSWD_HARDERROR           = 2
	KRB5_KPASSWD_AUTHERROR           = 3
	KRB5_KPASSWD_SOFTERROR           = 4
	KRB5_KPASSWD_ACCESSDENIED        = 5
	KRB5_KPASSWD_BAD_VERSION         = 6
	KRB5_KPASSWD_INITIAL_FLAG_NEEDED = 7
)

// ChangePasswd changes the password of the client using an admin "Set Password"
// operation (RFC 3244 with TargName/TargRealm). Requires "Reset Password"
// rights on the target account.
func (cl *Client) ChangePasswd(newPasswd string) (bool, error) {
	ASReq, err := messages.NewASReqForChgPasswd(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return false, err
	}
	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return false, err
	}

	msg, key, err := kadmin.ChangePasswdMsg(cl.Credentials.CName(), cl.Credentials.Domain(), newPasswd, ASRep.Ticket, ASRep.DecryptedEncPart.Key)
	if err != nil {
		return false, err
	}
	r, err := cl.sendToKPasswd(msg)
	if err != nil {
		return false, err
	}
	err = r.Decrypt(key)
	if err != nil {
		return false, err
	}
	if r.ResultCode != KRB5_KPASSWD_SUCCESS {
		return false, fmt.Errorf("error response from kadmin: code: %d; result: %s; krberror: %v", r.ResultCode, r.Result, r.KRBError)
	}
	cl.Credentials.WithPassword(newPasswd)
	return true, nil
}

// ChangeOwnPasswd changes the client's own password using a self-service
// "Change Password" operation (RFC 3244 WITHOUT TargName/TargRealm).
// Per RFC 3244 §2, omitting TargName/TargRealm tells the KDC this is a
// self-change. Does NOT require "Reset Password" rights — works for any
// account (users and machine accounts) changing their own password.
func (cl *Client) ChangeOwnPasswd(newPasswd string) (bool, error) {
	ASReq, err := messages.NewASReqForChgPasswd(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return false, err
	}
	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return false, err
	}

	msg, key, err := kadmin.ChangeOwnPasswdMsg(newPasswd, cl.Credentials.CName(), cl.Credentials.Domain(), ASRep.Ticket, ASRep.DecryptedEncPart.Key)
	if err != nil {
		return false, err
	}
	r, err := cl.sendToKPasswd(msg)
	if err != nil {
		return false, err
	}
	err = r.Decrypt(key)
	if err != nil {
		return false, err
	}
	if r.ResultCode != KRB5_KPASSWD_SUCCESS {
		return false, fmt.Errorf("error response from kadmin: code: %d; result: %s; krberror: %v", r.ResultCode, r.Result, r.KRBError)
	}
	cl.Credentials.WithPassword(newPasswd)
	return true, nil
}

func (cl *Client) sendToKPasswd(msg kadmin.Request) (r kadmin.Reply, err error) {
	_, kps, err := cl.Config.GetKpasswdServers(cl.Credentials.Domain(), true)
	if err != nil {
		return
	}
	b, err := msg.Marshal()
	if err != nil {
		return
	}
	var rb []byte
	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		rb, err = dialSendUDP(kps, b)
		if err != nil {
			return
		}
	} else {
		rb, err = dialSendTCP(kps, b)
		if err != nil {
			return
		}
	}
	err = r.Unmarshal(rb)
	return
}
