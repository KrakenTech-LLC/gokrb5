package client

import (
	"crypto/rand"
	"github.com/KrakenTech-LLC/gokrb5/v8/crypto"
	"github.com/KrakenTech-LLC/gokrb5/v8/crypto/etype"
	"github.com/KrakenTech-LLC/gokrb5/v8/iana/errorcode"
	"github.com/KrakenTech-LLC/gokrb5/v8/iana/keyusage"
	"github.com/KrakenTech-LLC/gokrb5/v8/iana/patype"
	"github.com/KrakenTech-LLC/gokrb5/v8/krberror"
	"github.com/KrakenTech-LLC/gokrb5/v8/messages"
	"github.com/KrakenTech-LLC/gokrb5/v8/pki"
	"github.com/KrakenTech-LLC/gokrb5/v8/types"
	"math/big"
)

// ASExchange performs an AS exchange for the client to retrieve a TGT.
func (cl *Client) ASExchange(realm string, ASReq messages.ASReq, referral int) (messages.ASRep, error) {
	if ok, err := cl.IsConfigured(); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.ConfigError, "AS Exchange cannot be performed")
	}

	// Set PAData if required
	err := setPAData(cl, nil, &ASReq)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: issue with setting PAData on AS_REQ")
	}

	b, err := ASReq.Marshal()
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ")
	}
	var ASRep messages.ASRep

	rb, err := cl.sendToKDC(b, realm)
	if err != nil {
		if e, ok := err.(messages.KRBError); ok {
			switch e.ErrorCode {
			case errorcode.KDC_ERR_PREAUTH_REQUIRED, errorcode.KDC_ERR_PREAUTH_FAILED:
				// From now on assume this client will need to do this pre-auth and set the PAData
				cl.settings.assumePreAuthentication = true
				err = setPAData(cl, &e, &ASReq)
				if err != nil {
					return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData for pre-authentication required")
				}
				b, err := ASReq.Marshal()
				if err != nil {
					return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ with PAData")
				}
				rb, err = cl.sendToKDC(b, realm)
				if err != nil {
					if _, ok := err.(messages.KRBError); ok {
						return messages.ASRep{}, krberror.Errorf(err, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC")
					}
					return messages.ASRep{}, krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
				}
			case errorcode.KDC_ERR_WRONG_REALM:
				// Client referral https://tools.ietf.org/html/rfc6806.html#section-7
				if referral > 5 {
					return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "maximum number of client referrals exceeded")
				}
				referral++
				return cl.ASExchange(e.CRealm, ASReq, referral)
			default:
				return messages.ASRep{}, krberror.Errorf(err, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC")
			}
		} else {
			return messages.ASRep{}, krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
		}
	}
	err = ASRep.Unmarshal(rb)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed to process the AS_REP")
	}
	if ok, err := ASRep.Verify(cl.Config, cl.Credentials, ASReq); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: AS_REP is not valid or client password/keytab incorrect")
	}
	return ASRep, nil
}

// setPAData adds pre-authentication data to the AS_REQ.
func setPAData(cl *Client, krberr *messages.KRBError, ASReq *messages.ASReq) error {
	if !cl.settings.DisablePAFXFAST() {
		pa := types.PAData{PADataType: patype.PA_REQ_ENC_PA_REP}
		ASReq.PAData = append(ASReq.PAData, pa)
	}

	// Handle certificate-based authentication (PKINIT)
	if cl.Credentials.HasCertificate() {
		return setPKINITPAData(cl, ASReq)
	}

	if cl.settings.AssumePreAuthentication() {
		// Identify the etype to use to encrypt the PA Data
		var et etype.EType
		var err error
		var key types.EncryptionKey
		var kvno int
		if krberr == nil {
			// This is not in response to an error from the KDC. It is preemptive or renewal
			// There is no KRB Error that tells us the etype to use
			etn := cl.settings.preAuthEType // Use the etype that may have previously been negotiated
			if etn == 0 {
				etn = int32(cl.Config.LibDefaults.PreferredPreauthTypes[0]) // Resort to config
			}
			et, err = crypto.GetEtype(etn)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting etype for pre-auth encryption")
			}
			key, kvno, err = cl.Key(et, 0, nil)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting key from credentials")
			}
		} else {
			// Get the etype to use from the PA data in the KRBError e-data
			et, err = preAuthEType(krberr)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting etype for pre-auth encryption")
			}
			cl.settings.preAuthEType = et.GetETypeID() // Set the etype that has been defined for potential future use
			key, kvno, err = cl.Key(et, 0, krberr)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting key from credentials")
			}
		}
		// Generate the PA data
		paTSb, err := types.GetPAEncTSEncAsnMarshalled()
		if err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "error creating PAEncTSEnc for Pre-Authentication")
		}
		paEncTS, err := crypto.GetEncryptedData(paTSb, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, kvno)
		if err != nil {
			return krberror.Errorf(err, krberror.EncryptingError, "error encrypting pre-authentication timestamp")
		}
		pb, err := paEncTS.Marshal()
		if err != nil {
			return krberror.Errorf(err, krberror.EncodingError, "error marshaling the PAEncTSEnc encrypted data")
		}
		pa := types.PAData{
			PADataType:  patype.PA_ENC_TIMESTAMP,
			PADataValue: pb,
		}
		// Look for and delete any exiting patype.PA_ENC_TIMESTAMP
		for i, pa := range ASReq.PAData {
			if pa.PADataType == patype.PA_ENC_TIMESTAMP {
				ASReq.PAData[i] = ASReq.PAData[len(ASReq.PAData)-1]
				ASReq.PAData = ASReq.PAData[:len(ASReq.PAData)-1]
			}
		}
		ASReq.PAData = append(ASReq.PAData, pa)
	}
	return nil
}

// preAuthEType establishes what encryption type to use for pre-authentication from the KRBError returned from the KDC.
func preAuthEType(krberr *messages.KRBError) (etype etype.EType, err error) {
	//RFC 4120 5.2.7.5 covers the preference order of ETYPE-INFO2 and ETYPE-INFO.
	var etypeID int32
	var pas types.PADataSequence
	e := pas.Unmarshal(krberr.EData)
	if e != nil {
		err = krberror.Errorf(e, krberror.EncodingError, "error unmashalling KRBError data")
		return
	}
Loop:
	for _, pa := range pas {
		switch pa.PADataType {
		case patype.PA_ETYPE_INFO2:
			info, e := pa.GetETypeInfo2()
			if e != nil {
				err = krberror.Errorf(e, krberror.EncodingError, "error unmashalling ETYPE-INFO2 data")
				return
			}
			etypeID = info[0].EType
			break Loop
		case patype.PA_ETYPE_INFO:
			info, e := pa.GetETypeInfo()
			if e != nil {
				err = krberror.Errorf(e, krberror.EncodingError, "error unmashalling ETYPE-INFO data")
				return
			}
			etypeID = info[0].EType
		}
	}
	etype, e = crypto.GetEtype(etypeID)
	if e != nil {
		err = krberror.Errorf(e, krberror.EncryptingError, "error creating etype")
		return
	}
	return etype, nil
}

// setPKINITPAData adds PKINIT pre-authentication data to the AS_REQ
func setPKINITPAData(cl *Client, ASReq *messages.ASReq) error {
	cert := cl.Credentials.Certificate()
	privateKey := cl.Credentials.PrivateKey()
	caCerts := cl.Credentials.CACerts()

	if cert == nil || privateKey == nil {
		return krberror.New(krberror.KRBMsgError, "certificate or private key not available for PKINIT")
	}

	// Generate random nonce for this request
	nonceBig, err := rand.Int(rand.Reader, big.NewInt(2147483647)) // Max int32
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "error generating nonce for PKINIT")
	}
	nonce := int32(nonceBig.Int64())

	// Marshal AS-REQ body to calculate PAChecksum
	asReqBodyBytes, err := ASReq.ReqBody.Marshal()
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error marshaling AS-REQ body for PKINIT checksum")
	}

	// Create PKINIT PAData with proper PAChecksum
	pkInitPAData, err := pki.CreatePKINITPADataWithChecksum(cert, privateKey, nonce, caCerts, asReqBodyBytes)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "error creating PKINIT PAData: %v", err)
	}

	// Add to AS_REQ
	ASReq.PAData = append(ASReq.PAData, *pkInitPAData)

	return nil
}
