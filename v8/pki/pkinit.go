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
	"strings"
	"time"

	"github.com/KrakenTech-LLC/gokrb5/v8/iana/patype"
	"github.com/KrakenTech-LLC/gokrb5/v8/types"
	"software.sslmate.com/src/go-pkcs12"
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
	ClientPublicValue *asn1.RawValue          `asn1:"explicit,optional,tag:1"` // DH public key
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

// CreatePKINITAuthPackWithChecksum creates an AuthPack with PAChecksum calculated from AS-REQ body
func CreatePKINITAuthPackWithChecksum(clientCert *x509.Certificate, nonce int32, asReqBody []byte) (*AuthPack, error) {
	if clientCert == nil {
		return nil, errors.New("client certificate is required")
	}

	// Calculate PAChecksum using SHA-256 of AS-REQ body
	hash := sha256.Sum256(asReqBody)
	paChecksum := hash[:]

	// Create PKAuthenticator with checksum
	pkAuth := PKAuthenticator{
		CusecAndCtime: time.Now().UTC(), // Current time
		Nonce:         nonce,
		PAChecksum:    paChecksum, // Checksum of AS-REQ body
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

// signAuthPackWithCMS signs the AuthPack using CMS SignedData per RFC 4556
func signAuthPackWithCMS(authPack *AuthPack, cert *x509.Certificate, privateKey interface{}, caCerts []*x509.Certificate) ([]byte, error) {
	// 1. Marshal AuthPack to DER
	authPackBytes, err := asn1.Marshal(*authPack)
	if err != nil {
		return nil, errors.New("failed to marshal AuthPack: " + err.Error())
	}

	// 2. Create content hash (SHA-256) - this should be the hash of the content
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

	// 4. Create SignerInfo with proper structure
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

	// 5. Prepare certificates for inclusion - always include client cert
	var certRawValues []asn1.RawValue
	certRawValues = append(certRawValues, asn1.RawValue{FullBytes: cert.Raw})
	for _, caCert := range caCerts {
		certRawValues = append(certRawValues, asn1.RawValue{FullBytes: caCert.Raw})
	}

	// 6. Create SignedData with embedded content (try attached signature)
	signedData := SignedData{
		Version: 1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{Algorithm: OIDSHA256},
		},
		ContentInfo: ContentInfo{
			ContentType: OIDData,
			Content: asn1.RawValue{
				Tag:        asn1.TagOctetString,
				Class:      asn1.ClassUniversal,
				IsCompound: false,
				Bytes:      authPackBytes,
			},
		},
		Certificates: certRawValues,
		SignerInfos:  []SignerInfo{signerInfo},
	}

	// 7. Marshal SignedData and wrap in ContentInfo
	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, errors.New("failed to marshal SignedData: " + err.Error())
	}

	// 8. Create final ContentInfo wrapper
	contentInfo := ContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{FullBytes: signedDataBytes},
	}

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

// ExtractPrincipalFromCertificate extracts the best Kerberos principal from a certificate
// This function tries multiple methods to find the correct principal name for PKINIT authentication
func ExtractPrincipalFromCertificate(cert *x509.Certificate) string {
	// 1. Try to extract UPN from SAN extension (most reliable for PKINIT)
	upn := extractUPNFromSAN(cert)
	if upn != "" {
		// Extract just the username part before @
		if parts := strings.Split(upn, "@"); len(parts) == 2 {
			return parts[0]
		}
	}

	// 2. Try DNS names in SAN
	for _, dns := range cert.DNSNames {
		if strings.Contains(dns, ".") {
			// Extract hostname from FQDN
			parts := strings.Split(dns, ".")
			if len(parts) > 0 {
				return parts[0]
			}
		}
	}

	// 3. Try email addresses
	for _, email := range cert.EmailAddresses {
		if strings.Contains(email, "@") {
			parts := strings.Split(email, "@")
			if len(parts) == 2 {
				return parts[0]
			}
		}
	}

	// 4. Try Common Name
	cn := cert.Subject.CommonName
	if cn != "" {
		// Remove $ suffix if present (machine accounts)
		return strings.TrimSuffix(cn, "$")
	}

	return ""
}

// GetPrincipalVariations returns all possible principal name variations for a certificate
// This is used when the primary principal extraction fails and we need to try alternatives
func GetPrincipalVariations(cert *x509.Certificate) []string {
	var variations []string

	// Get the primary principal
	primary := ExtractPrincipalFromCertificate(cert)
	if primary != "" {
		variations = append(variations, primary)
	}

	// Add UPN-based variations
	upn := extractUPNFromSAN(cert)
	if upn != "" && strings.Contains(upn, "@") {
		parts := strings.Split(upn, "@")
		if len(parts) == 2 {
			username := parts[0]
			variations = append(variations,
				username,
				username+"$",                      // Machine account format
				"host/"+username,                  // Service principal format
				"host/"+strings.ToLower(username), // Service principal lowercase
				strings.ToLower(username),         // Lowercase version
				strings.ToUpper(username),         // Uppercase version
			)
		}
	}

	// Add Common Name variations
	cn := cert.Subject.CommonName
	if cn != "" {
		variations = append(variations,
			cn,                          // Full CN
			strings.TrimSuffix(cn, "$"), // CN without $
			strings.ToLower(cn),         // Lowercase CN
			strings.ToUpper(cn),         // Uppercase CN
			strings.ToLower(strings.TrimSuffix(cn, "$")), // Lowercase without $
			strings.ToUpper(strings.TrimSuffix(cn, "$")), // Uppercase without $
		)

		// Add service principal variations for CN
		baseCN := strings.TrimSuffix(cn, "$")
		variations = append(variations,
			"host/"+strings.ToLower(baseCN),
			"host/"+strings.ToUpper(baseCN),
		)
	}

	// Add DNS name variations
	for _, dns := range cert.DNSNames {
		if strings.Contains(dns, ".") {
			parts := strings.Split(dns, ".")
			if len(parts) > 0 {
				hostname := parts[0]
				variations = append(variations,
					hostname,
					strings.ToLower(hostname),
					strings.ToUpper(hostname),
					"host/"+hostname,
					"host/"+strings.ToLower(hostname),
					"host/"+strings.ToUpper(hostname),
				)
			}
		}
	}

	// Remove duplicates while preserving order
	seen := make(map[string]bool)
	var unique []string
	for _, v := range variations {
		if v != "" && !seen[v] {
			seen[v] = true
			unique = append(unique, v)
		}
	}

	return unique
}

// PKINITAuthResult represents the result of a PKINIT authentication attempt
type PKINITAuthResult struct {
	Success             bool
	SuccessfulPrincipal string
	AttemptedPrincipals []string
	LastError           error
	Duration            time.Duration
}

// AuthenticateWithPKINIT performs PKINIT authentication with automatic principal discovery
// This function tries multiple principal variations until one succeeds
func AuthenticateWithPKINIT(cert *x509.Certificate, privateKey interface{}, caCerts []*x509.Certificate, realm string, kdc string) (*PKINITAuthResult, error) {
	if cert == nil {
		return nil, errors.New("certificate is required")
	}
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}
	if realm == "" {
		return nil, errors.New("realm is required")
	}
	if kdc == "" {
		return nil, errors.New("KDC address is required")
	}

	startTime := time.Now()
	result := &PKINITAuthResult{
		Success:             false,
		AttemptedPrincipals: []string{},
	}

	// Get all possible principal variations
	principals := GetPrincipalVariations(cert)
	if len(principals) == 0 {
		return result, errors.New("no valid principals found in certificate")
	}

	// Try each principal until one works
	for _, principal := range principals {
		result.AttemptedPrincipals = append(result.AttemptedPrincipals, principal)

		// This would need to be implemented with the actual client authentication
		// For now, this is a placeholder that shows the structure
		// The actual implementation would use the gokrb5 client

		// TODO: Implement actual authentication attempt here
		// success, err := tryAuthenticationWithPrincipal(principal, cert, privateKey, caCerts, realm, kdc)
		// if success {
		//     result.Success = true
		//     result.SuccessfulPrincipal = principal
		//     break
		// }
		// result.LastError = err
	}

	result.Duration = time.Since(startTime)
	return result, result.LastError
}

// ValidateCertificateForPKINIT validates that a certificate is suitable for PKINIT authentication
func ValidateCertificateForPKINIT(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	// Check if certificate has expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return errors.New("certificate is not yet valid")
	}
	if now.After(cert.NotAfter) {
		return errors.New("certificate has expired")
	}

	// Check key usage - should allow digital signature
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("certificate does not allow digital signatures")
	}

	// Check extended key usage - should allow client authentication
	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		return errors.New("certificate does not allow client authentication")
	}

	// Try to extract a principal name
	principal := ExtractPrincipalFromCertificate(cert)
	if principal == "" {
		return errors.New("no valid principal name found in certificate")
	}

	return nil
}

// GetCertificateInfo returns detailed information about a certificate for debugging
func GetCertificateInfo(cert *x509.Certificate) map[string]interface{} {
	if cert == nil {
		return map[string]interface{}{"error": "certificate is nil"}
	}

	info := map[string]interface{}{
		"subject":              cert.Subject.String(),
		"issuer":               cert.Issuer.String(),
		"serial_number":        cert.SerialNumber.String(),
		"not_before":           cert.NotBefore,
		"not_after":            cert.NotAfter,
		"key_usage":            cert.KeyUsage,
		"ext_key_usage":        cert.ExtKeyUsage,
		"dns_names":            cert.DNSNames,
		"email_addresses":      cert.EmailAddresses,
		"ip_addresses":         cert.IPAddresses,
		"extracted_principal":  ExtractPrincipalFromCertificate(cert),
		"principal_variations": GetPrincipalVariations(cert),
		"upn_from_san":         extractUPNFromSAN(cert),
	}

	// Add validation result
	if err := ValidateCertificateForPKINIT(cert); err != nil {
		info["validation_error"] = err.Error()
	} else {
		info["validation_status"] = "valid for PKINIT"
	}

	return info
}

// LoadFromPFX loads certificate, private key, and CA certificates from a PFX/PKCS12 file
// This is a convenience function that wraps pkcs12.DecodeChain
func LoadFromPFX(pfxData []byte, password string) (privateKey interface{}, cert *x509.Certificate, caCerts []*x509.Certificate, err error) {
	return pkcs12.DecodeChain(pfxData, password)
}

// LoadFromPFXFile loads certificate, private key, and CA certificates from a PFX/PKCS12 file path
func LoadFromPFXFile(pfxPath string, password string) (privateKey interface{}, cert *x509.Certificate, caCerts []*x509.Certificate, err error) {
	// This would need os import, but keeping it simple for now
	// Applications can use LoadFromPFX with os.ReadFile(pfxPath)
	return nil, nil, nil, errors.New("use LoadFromPFX with os.ReadFile(pfxPath)")
}

// extractUPNFromSAN extracts the UPN (User Principal Name) from the SAN extension
func extractUPNFromSAN(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "2.5.29.17" { // Subject Alternative Name
			// Look for UPN pattern in the raw bytes
			upn := findUPNInBytes(ext.Value)
			if upn != "" {
				return upn
			}
		}
	}
	return ""
}

// findUPNInBytes searches for UPN pattern in raw certificate extension bytes
func findUPNInBytes(data []byte) string {
	// Look for email-like patterns (contains @)
	for i := 0; i < len(data)-1; i++ {
		if data[i] == '@' {
			// Found @, now extract the full UPN
			// Look backwards for the start
			start := i - 1
			for start >= 0 && isValidUPNChar(data[start]) {
				start--
			}
			start++

			// Look forwards for the end
			end := i + 1
			for end < len(data) && isValidUPNChar(data[end]) {
				end++
			}

			if start < i && end > i+1 {
				candidate := string(data[start:end])
				// Validate it looks like a UPN
				if strings.Contains(candidate, "@") && len(candidate) > 3 {
					return candidate
				}
			}
		}
	}
	return ""
}

// isValidUPNChar checks if a character is valid in a UPN
func isValidUPNChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '.' || b == '-' || b == '_' || b == '$'
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

// CreatePKINITPADataWithChecksum creates PA-PK-AS-REQ PAData with proper PAChecksum
func CreatePKINITPADataWithChecksum(clientCert *x509.Certificate, privateKey interface{}, nonce int32, caCerts []*x509.Certificate, asReqBody []byte) (*types.PAData, error) {
	if clientCert == nil {
		return nil, errors.New("client certificate is required")
	}
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}

	// Create AuthPack with PAChecksum
	authPack, err := CreatePKINITAuthPackWithChecksum(clientCert, nonce, asReqBody)
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
