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

// ChangePasswd changes the password of the client to the value provided.
// Uses RFC 3244 Set Password protocol (version 0xff80) with ChangePasswdData.
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

// ChangeOwnPasswd changes the client's password using RFC 2222 Change Password
// protocol (version 0x0001). This uses a simple password payload instead of the
// ChangePasswdData ASN.1 structure. Some KDCs (Windows AD) treat the 0xff80
// Set Password version as an admin operation requiring "Reset Password" rights,
// while the 0x0001 version is treated as a self-service "Change Password"
// operation that any user/computer can perform on their own account.
func (cl *Client) ChangeOwnPasswd(newPasswd string) (bool, error) {
	ASReq, err := messages.NewASReqForChgPasswd(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return false, err
	}
	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return false, err
	}

	msg, key, err := kadmin.ChangeOwnPasswdMsg(newPasswd, ASRep.Ticket, ASRep.DecryptedEncPart.Key)
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
