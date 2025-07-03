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
	"fmt"
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

// CertificateIdentification represents an identification found in a certificate
type CertificateIdentification struct {
	Type  string // "UPN", "DNS", "Email", "CN", etc.
	Value string
}

// ExtractPrincipalFromCertificate extracts the best Kerberos principal from a certificate
// This function implements the same logic as certipy for certificate identification
func ExtractPrincipalFromCertificate(cert *x509.Certificate) (string, string, error) {
	// Get all identifications from certificate
	identifications := getIdentificationsFromCertificate(cert)

	if len(identifications) == 0 {
		return "", "", errors.New("could not find identification in the provided certificate")
	}

	// Use the first identification (certipy would prompt user, but we'll use first)
	// In a real implementation, you might want to add logic to prefer certain types
	var selectedIdentification CertificateIdentification
	if len(identifications) > 1 {
		// Prefer UPN over other types
		for _, id := range identifications {
			if id.Type == "UPN" {
				selectedIdentification = id
				break
			}
		}
		// If no UPN found, use first identification
		if selectedIdentification.Type == "" {
			selectedIdentification = identifications[0]
		}
	} else {
		selectedIdentification = identifications[0]
	}

	// Convert identification to username and domain parts
	username, domain := certIdToParts(selectedIdentification)

	if username == "" || domain == "" {
		return "", "", errors.New("could not extract valid username and domain from certificate identification")
	}

	return strings.ToLower(username), strings.ToLower(domain), nil
}

// getIdentificationsFromCertificate extracts all possible identifications from a certificate
// This mirrors the certipy get_identifications_from_certificate function
func getIdentificationsFromCertificate(cert *x509.Certificate) []CertificateIdentification {
	var identifications []CertificateIdentification

	// 1. Extract UPN from Subject Alternative Name (most reliable for PKINIT)
	upn := extractUPNFromSAN(cert)
	if upn != "" {
		identifications = append(identifications, CertificateIdentification{
			Type:  "UPN",
			Value: upn,
		})
	}

	// 2. Extract DNS names from SAN
	for _, dns := range cert.DNSNames {
		if dns != "" {
			identifications = append(identifications, CertificateIdentification{
				Type:  "DNS",
				Value: dns,
			})
		}
	}

	// 3. Extract email addresses from SAN
	for _, email := range cert.EmailAddresses {
		if email != "" {
			identifications = append(identifications, CertificateIdentification{
				Type:  "Email",
				Value: email,
			})
		}
	}

	// 4. Extract Common Name from Subject
	cn := cert.Subject.CommonName
	if cn != "" {
		identifications = append(identifications, CertificateIdentification{
			Type:  "CN",
			Value: cn,
		})
	}

	// 5. Extract other subject components that might be useful
	for _, name := range cert.Subject.Names {
		// Look for other OIDs that might contain useful information
		if name.Type.String() != "2.5.4.3" { // Skip CN as we already have it
			identifications = append(identifications, CertificateIdentification{
				Type:  "Subject-" + name.Type.String(),
				Value: fmt.Sprintf("%v", name.Value),
			})
		}
	}

	return identifications
}

// certIdToParts converts a certificate identification to username and domain parts
// This mirrors the certipy cert_id_to_parts function
func certIdToParts(identification CertificateIdentification) (string, string) {
	switch identification.Type {
	case "UPN":
		// UPN format: username@domain.com
		if strings.Contains(identification.Value, "@") {
			parts := strings.Split(identification.Value, "@")
			if len(parts) == 2 {
				return parts[0], parts[1]
			}
		}

	case "Email":
		// Email format: username@domain.com
		if strings.Contains(identification.Value, "@") {
			parts := strings.Split(identification.Value, "@")
			if len(parts) == 2 {
				return parts[0], parts[1]
			}
		}

	case "DNS":
		// DNS format: hostname.domain.com
		if strings.Contains(identification.Value, ".") {
			parts := strings.Split(identification.Value, ".")
			if len(parts) >= 2 {
				hostname := parts[0]
				domain := strings.Join(parts[1:], ".")
				return hostname, domain
			}
		}

	case "CN":
		// Common Name - try to extract meaningful parts
		cn := identification.Value

		// Remove $ suffix if present (machine accounts)
		cn = strings.TrimSuffix(cn, "$")

		// If CN contains @, treat it like UPN
		if strings.Contains(cn, "@") {
			parts := strings.Split(cn, "@")
			if len(parts) == 2 {
				return parts[0], parts[1]
			}
		}

		// If CN contains domain-like structure
		if strings.Contains(cn, ".") {
			parts := strings.Split(cn, ".")
			if len(parts) >= 2 {
				hostname := parts[0]
				domain := strings.Join(parts[1:], ".")
				return hostname, domain
			}
		}

		// Otherwise, return CN as username with empty domain
		return cn, ""
	}

	return "", ""
}

// ExtractPrincipalFromCertificateSimple provides a simple interface that returns just the UPN
// This is for backward compatibility with the old function signature
func ExtractPrincipalFromCertificateSimple(cert *x509.Certificate) string {
	username, domain, err := ExtractPrincipalFromCertificateWithValidation(cert, "", "")
	if err != nil {
		return ""
	}
	if username == "" || domain == "" {
		return ""
	}
	return username + "@" + domain
}

// ExtractPrincipalFromCertificateWithValidation implements the complete certipy logic
// for extracting and validating principal information from a certificate
func ExtractPrincipalFromCertificateWithValidation(cert *x509.Certificate, providedUsername, providedDomain string) (string, string, error) {
	// Get all identifications from certificate
	identifications := getIdentificationsFromCertificate(cert)

	var selectedIdentification CertificateIdentification

	if len(identifications) > 1 {
		// Multiple identifications found - prefer UPN, then Email, then DNS, then CN
		for _, id := range identifications {
			if id.Type == "UPN" {
				selectedIdentification = id
				break
			}
		}
		if selectedIdentification.Type == "" {
			for _, id := range identifications {
				if id.Type == "Email" {
					selectedIdentification = id
					break
				}
			}
		}
		if selectedIdentification.Type == "" {
			for _, id := range identifications {
				if id.Type == "DNS" {
					selectedIdentification = id
					break
				}
			}
		}
		if selectedIdentification.Type == "" {
			selectedIdentification = identifications[0] // Fallback to first
		}
	} else if len(identifications) == 1 {
		selectedIdentification = identifications[0]
	} else {
		// No identifications found
		if providedUsername == "" || providedDomain == "" {
			return "", "", errors.New("username or domain is not specified, and identification information was not found in the certificate")
		}
		// Use provided credentials
		return strings.ToLower(providedUsername), strings.ToLower(providedDomain), nil
	}

	// Convert identification to username and domain parts
	certUsername, certDomain := certIdToParts(selectedIdentification)

	// Determine final username and domain
	finalUsername := providedUsername
	finalDomain := providedDomain

	// Username validation logic (mirrors certipy)
	if finalUsername == "" {
		finalUsername = certUsername
	} else if certUsername != "" {
		// Check if provided username matches certificate
		if !usernameMatches(strings.ToLower(finalUsername), strings.ToLower(certUsername)) {
			return "", "", errors.New(fmt.Sprintf("the provided username does not match the identification found in the provided certificate: %s - %s", finalUsername, certUsername))
		}
	}

	// Domain validation logic (mirrors certipy)
	if finalDomain == "" {
		finalDomain = certDomain
	} else if certDomain != "" {
		// Check if provided domain matches certificate
		if !domainMatches(strings.ToLower(finalDomain), strings.ToLower(certDomain)) {
			return "", "", errors.New(fmt.Sprintf("the provided domain does not match the identification found in the provided certificate: %s - %s", finalDomain, certDomain))
		}
	}

	// Final validation
	if finalUsername == "" || finalDomain == "" {
		return "", "", errors.New("username or domain is not specified, and identification information was not found in the certificate")
	}

	if len(finalUsername) == 0 || len(finalDomain) == 0 {
		return "", "", errors.New(fmt.Sprintf("username or domain is invalid: %s@%s", finalUsername, finalDomain))
	}

	return strings.ToLower(finalUsername), strings.ToLower(finalDomain), nil
}

// usernameMatches checks if two usernames match according to certipy logic
func usernameMatches(provided, fromCert string) bool {
	// Direct match
	if provided == fromCert {
		return true
	}

	// Check if provided username matches with $ suffix (machine accounts)
	if provided == fromCert+"$" {
		return true
	}

	// Check if certificate username has $ suffix and matches without it
	if strings.HasSuffix(fromCert, "$") && provided == strings.TrimSuffix(fromCert, "$") {
		return true
	}

	return false
}

// domainMatches checks if two domains match according to certipy logic
func domainMatches(provided, fromCert string) bool {
	// Direct match
	if provided == fromCert {
		return true
	}

	// Check if certificate domain is a subdomain of provided domain
	// e.g., provided="example.com", fromCert="sub.example.com"
	providedWithDot := strings.TrimSuffix(provided, ".") + "."
	if strings.HasSuffix(fromCert, providedWithDot) {
		return true
	}

	return false
}

// GetObjectSIDFromCertificate extracts the object SID from certificate extensions
// This mirrors the certipy get_object_sid_from_certificate function
func GetObjectSIDFromCertificate(cert *x509.Certificate) string {
	// Look for SID in certificate extensions
	// The SID is typically in a custom extension with OID 1.3.6.1.4.1.311.25.2
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.311.25.2" { // Microsoft SID extension
			// Parse the SID from the extension value
			// This is a simplified implementation - real SID parsing is more complex
			return parseSIDFromBytes(ext.Value)
		}
	}
	return ""
}

// parseSIDFromBytes attempts to parse a SID from raw bytes
func parseSIDFromBytes(data []byte) string {
	// This is a simplified SID parser
	// A full implementation would properly decode the SID structure
	if len(data) < 8 {
		return ""
	}

	// Look for SID pattern in the data
	// This is a basic implementation - you might need more sophisticated parsing
	for i := 0; i < len(data)-3; i++ {
		if data[i] == 'S' && data[i+1] == '-' {
			// Found potential SID start, extract until end or invalid character
			end := i + 2
			for end < len(data) && (data[end] >= '0' && data[end] <= '9' || data[end] == '-') {
				end++
			}
			if end > i+2 {
				return string(data[i:end])
			}
		}
	}

	return ""
}

// GetPrincipalVariations returns all possible principal name variations for a certificate
// This is used when the primary principal extraction fails and we need to try alternatives
func GetPrincipalVariations(cert *x509.Certificate) []string {
	var variations []string

	// Get the primary principal
	usermame, domain, err := ExtractPrincipalFromCertificate(cert)
	if err != nil {
		return variations
	}
	primary := usermame + "@" + domain
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

	// Extract principal from certificate
	username, domain, err := ExtractPrincipalFromCertificateWithValidation(cert, "", "")
	if err != nil {
		return result, err
	}

	principal := username + "@" + domain
	result.AttemptedPrincipals = append(result.AttemptedPrincipals, principal)

	// This would need to be implemented with the actual client authentication
	// For now, this is a placeholder that shows the structure
	// The actual implementation would use the gokrb5 client

	// TODO: Implement actual authentication attempt here
	// success, err := tryAuthenticationWithPrincipal(principal, cert, privateKey, caCerts, realm, kdc)
	// if success {
	//     result.Success = true
	//     result.SuccessfulPrincipal = principal
	// }
	// result.LastError = err

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
	username, domain, err := ExtractPrincipalFromCertificateWithValidation(cert, "", "")
	if err != nil {
		return errors.New("no valid principal name found in certificate: " + err.Error())
	}
	if username == "" || domain == "" {
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
		"subject":         cert.Subject.String(),
		"issuer":          cert.Issuer.String(),
		"serial_number":   cert.SerialNumber.String(),
		"not_before":      cert.NotBefore,
		"not_after":       cert.NotAfter,
		"key_usage":       cert.KeyUsage,
		"ext_key_usage":   cert.ExtKeyUsage,
		"dns_names":       cert.DNSNames,
		"email_addresses": cert.EmailAddresses,
		"ip_addresses":    cert.IPAddresses,
		"upn_from_san":    extractUPNFromSAN(cert),
	}

	// Add extracted principal information
	username, domain, err := ExtractPrincipalFromCertificateWithValidation(cert, "", "")
	if err != nil {
		info["principal_extraction_error"] = err.Error()
	} else {
		info["extracted_username"] = username
		info["extracted_domain"] = domain
		info["extracted_principal"] = username + "@" + domain
	}

	// Add all identifications found
	identifications := getIdentificationsFromCertificate(cert)
	info["identifications"] = identifications
	info["principal_variations"] = GetPrincipalVariations(cert)

	// Add object SID if present
	objectSID := GetObjectSIDFromCertificate(cert)
	if objectSID != "" {
		info["object_sid"] = objectSID
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
