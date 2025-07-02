package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"github.com/KrakenTech-LLC/gokrb5/v8/iana/patype"
	"github.com/KrakenTech-LLC/gokrb5/v8/types"
)

// PKAuthenticator represents the PA-PK-AS-REQ structure for PKINIT
type PKAuthenticator struct {
	CusecAndCtime time.Time `asn1:"explicit,tag:0"`
	Nonce         int32     `asn1:"explicit,tag:1"`
	PAChecksum    []byte    `asn1:"explicit,optional,tag:2"`
}

// AuthPack represents the AuthPack structure for PKINIT
type AuthPack struct {
	PKAuthenticator   PKAuthenticator         `asn1:"explicit,tag:0"`
	ClientPublicValue interface{}             `asn1:"explicit,optional,tag:1"` // DH public key
	SupportedCMSTypes []asn1.ObjectIdentifier `asn1:"explicit,optional,tag:2"`
	ClientDHNonce     []byte                  `asn1:"explicit,optional,tag:3"`
}

// PA_PK_AS_REQ represents the PA-PK-AS-REQ structure
type PA_PK_AS_REQ struct {
	SignedAuthPack    []byte      `asn1:"explicit,optional,tag:0"` // CMS SignedData
	TrustedCertifiers []TrustedCA `asn1:"explicit,optional,tag:1"`
	KDCPKId           []byte      `asn1:"explicit,optional,tag:2"`
}

// TrustedCA represents a trusted certificate authority
type TrustedCA struct {
	CaName                  []byte   `asn1:"explicit,optional,tag:0"`
	CertificateSerialNumber *big.Int `asn1:"explicit,optional,tag:1"`
	SubjectKeyIdentifier    []byte   `asn1:"explicit,optional,tag:2"`
}

// PA_PK_AS_REP represents the PA-PK-AS-REP structure
type PA_PK_AS_REP struct {
	DHInfo     DHRepInfo `asn1:"explicit,optional,tag:0"`
	EncKeyPack []byte    `asn1:"explicit,optional,tag:1"` // CMS EnvelopedData
}

// DHRepInfo represents Diffie-Hellman reply information
type DHRepInfo struct {
	DHSignedData  []byte `asn1:"explicit,tag:0"` // CMS SignedData
	ServerDHNonce []byte `asn1:"explicit,optional,tag:1"`
}

// CMS/PKCS7 structures for signing
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type SignedData struct {
	Version          int                        `asn1:"default:1"`
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo      ContentInfo
	Certificates     []asn1.RawValue        `asn1:"implicit,optional,tag:0"`
	CRLs             []pkix.CertificateList `asn1:"implicit,optional,tag:1"`
	SignerInfos      []SignerInfo           `asn1:"set"`
}

type SignerInfo struct {
	Version                   int `asn1:"default:1"`
	SID                       SignerIdentifier
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttrs        []Attribute `asn1:"implicit,optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttrs      []Attribute `asn1:"implicit,optional,tag:1"`
}

type SignerIdentifier struct {
	IssuerAndSerialNumber IssuerAndSerialNumber
}

type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// OIDs for CMS
var (
	OIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDRSASHA256     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

// CreatePKINITAuthPack creates a basic AuthPack for PKINIT
func CreatePKINITAuthPack(clientCert *x509.Certificate, nonce int32) (*AuthPack, error) {
	if clientCert == nil {
		return nil, errors.New("client certificate is required")
	}

	// Create PKAuthenticator
	pkAuth := PKAuthenticator{
		CusecAndCtime: time.Now().UTC(), // Current time
		Nonce:         nonce,
		// PAChecksum would be calculated based on the AS-REQ
	}

	// Create AuthPack
	authPack := &AuthPack{
		PKAuthenticator: pkAuth,
		// ClientPublicValue would contain DH public key
		// SupportedCMSTypes would list supported algorithms
		// ClientDHNonce would be random bytes for DH exchange
	}

	return authPack, nil
}

// signAuthPackWithCMS signs the AuthPack using CMS SignedData
func signAuthPackWithCMS(authPack *AuthPack, cert *x509.Certificate, privateKey interface{}, caCerts []*x509.Certificate) ([]byte, error) {
	// 1. Marshal AuthPack to DER
	authPackBytes, err := asn1.Marshal(*authPack)
	if err != nil {
		return nil, errors.New("failed to marshal AuthPack: " + err.Error())
	}

	// 2. Create content hash (SHA-256)
	hash := sha256.Sum256(authPackBytes)

	// 3. Sign the hash with private key
	var signature []byte
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			return nil, errors.New("failed to sign with RSA key: " + err.Error())
		}
	default:
		return nil, errors.New("unsupported private key type")
	}

	// 4. Create SignerInfo
	signerInfo := SignerInfo{
		Version: 1,
		SID: SignerIdentifier{
			IssuerAndSerialNumber: IssuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
				SerialNumber: cert.SerialNumber,
			},
		},
		DigestAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OIDSHA256,
		},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OIDRSASHA256,
		},
		EncryptedDigest: signature,
	}

	// 5. Prepare certificates for inclusion
	var certRawValues []asn1.RawValue
	certRawValues = append(certRawValues, asn1.RawValue{FullBytes: cert.Raw})
	for _, caCert := range caCerts {
		certRawValues = append(certRawValues, asn1.RawValue{FullBytes: caCert.Raw})
	}

	// 6. Create SignedData
	signedData := SignedData{
		Version: 1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{Algorithm: OIDSHA256},
		},
		ContentInfo: ContentInfo{
			ContentType: OIDData,
			Content:     asn1.RawValue{FullBytes: authPackBytes},
		},
		Certificates: certRawValues,
		SignerInfos:  []SignerInfo{signerInfo},
	}

	// 7. Marshal SignedData
	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, errors.New("failed to marshal SignedData: " + err.Error())
	}

	// 8. Create ContentInfo wrapper
	contentInfo := ContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{FullBytes: signedDataBytes},
	}

	// 9. Marshal final ContentInfo
	return asn1.Marshal(contentInfo)
}

// createTrustedCertifiers creates TrustedCA entries from CA certificates
func createTrustedCertifiers(caCerts []*x509.Certificate) []TrustedCA {
	var trustedCAs []TrustedCA

	for _, caCert := range caCerts {
		trustedCA := TrustedCA{
			CaName:                  caCert.RawSubject,
			CertificateSerialNumber: caCert.SerialNumber,
		}

		// Add Subject Key Identifier if available
		for _, ext := range caCert.Extensions {
			if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 14}) { // Subject Key Identifier OID
				trustedCA.SubjectKeyIdentifier = ext.Value
				break
			}
		}

		trustedCAs = append(trustedCAs, trustedCA)
	}

	return trustedCAs
}

// CreatePKINITPAData creates PA-PK-AS-REQ PAData for certificate authentication
func CreatePKINITPAData(clientCert *x509.Certificate, privateKey interface{}, nonce int32, caCerts []*x509.Certificate) (*types.PAData, error) {
	if clientCert == nil {
		return nil, errors.New("client certificate is required")
	}
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}

	// Create AuthPack
	authPack, err := CreatePKINITAuthPack(clientCert, nonce)
	if err != nil {
		return nil, err
	}

	// Sign the AuthPack with CMS
	signedAuthPack, err := signAuthPackWithCMS(authPack, clientCert, privateKey, caCerts)
	if err != nil {
		return nil, errors.New("failed to sign AuthPack: " + err.Error())
	}

	// Create TrustedCertifiers from CA certificates
	var trustedCertifiers []TrustedCA
	if len(caCerts) > 0 {
		trustedCertifiers = createTrustedCertifiers(caCerts)
	}

	// Create PA-PK-AS-REQ structure
	pkAsReq := PA_PK_AS_REQ{
		SignedAuthPack:    signedAuthPack,
		TrustedCertifiers: trustedCertifiers,
		// KDCPKId could be set if we know which KDC certificate to use
	}

	pkAsReqBytes, err := asn1.Marshal(pkAsReq)
	if err != nil {
		return nil, err
	}

	// Create PAData
	paData := &types.PAData{
		PADataType:  patype.PA_PK_AS_REQ,
		PADataValue: pkAsReqBytes,
	}

	return paData, nil
}
