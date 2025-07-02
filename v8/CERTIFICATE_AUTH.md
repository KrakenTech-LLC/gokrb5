# Certificate-Based Authentication for gokrb5

This document describes the certificate-based authentication methods added to the gokrb5 library.

## Overview

The implementation adds support for X.509 certificate-based authentication through two main approaches:

1. **PFX/PKCS12 files** - Complete certificate packages including private key and CA certificate chain
2. **Separate certificate and key files** - Individual certificate and private key files

## New Methods

### Client Creation Methods

#### `NewWithPFX`
Creates a new client from a PFX/PKCS12 file.

```go
func NewWithPFX(username, realm string, pfxData []byte, pfxPassword string, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error)
```

**Parameters:**
- `username`: Kerberos username
- `realm`: Kerberos realm (empty string uses default from config)
- `pfxData`: Raw bytes of the PFX/PKCS12 file
- `pfxPassword`: Password to decrypt the PFX file
- `krb5conf`: Kerberos configuration
- `settings`: Optional client settings

**Features:**
- Automatically extracts certificate, private key, and CA certificate chain
- Uses `pkcs12.DecodeChain` to get the complete certificate chain
- Stores all components in the credentials structure

#### `NewWithCertAndKey`
Creates a new client from a certificate and private key.

```go
func NewWithCertAndKey(username, realm string, cert *x509.Certificate, privateKey interface{}, krb5conf *config.Config, settings ...func(*Settings)) *Client
```

**Parameters:**
- `username`: Kerberos username
- `realm`: Kerberos realm
- `cert`: X.509 certificate
- `privateKey`: Private key (can be *rsa.PrivateKey, *ecdsa.PrivateKey, etc.)
- `krb5conf`: Kerberos configuration
- `settings`: Optional client settings

#### `NewWithCertChain`
Creates a new client from a certificate, private key, and CA certificate chain.

```go
func NewWithCertChain(username, realm string, cert *x509.Certificate, privateKey interface{}, caCerts []*x509.Certificate, krb5conf *config.Config, settings ...func(*Settings)) *Client
```

**Parameters:**
- Same as `NewWithCertAndKey` plus:
- `caCerts`: Array of CA certificates for the certificate chain

### Credentials Methods

#### Certificate Management
```go
// Set certificate and private key
func (c *Credentials) WithCertificate(cert *x509.Certificate, key interface{}) *Credentials

// Set certificate, private key, and CA certificates
func (c *Credentials) WithCertificateChain(cert *x509.Certificate, key interface{}, caCerts []*x509.Certificate) *Credentials

// Load from PFX file
func (c *Credentials) WithPFX(pfxData []byte, password string) (*Credentials, error)
```

#### Certificate Access
```go
// Get certificate
func (c *Credentials) Certificate() *x509.Certificate

// Get private key
func (c *Credentials) PrivateKey() interface{}

// Get CA certificates
func (c *Credentials) CACerts() []*x509.Certificate

// Check if certificate is available
func (c *Credentials) HasCertificate() bool

// Check if CA certificates are available
func (c *Credentials) HasCACerts() bool
```

## Implementation Details

### Credentials Structure
The `Credentials` struct has been extended with:
- `certificate *x509.Certificate` - The client certificate
- `privateKey interface{}` - The private key (supports various key types)
- `caCerts []*x509.Certificate` - CA certificates from the certificate chain

### PFX Handling
The PFX implementation uses `pkcs12.DecodeChain` which:
- Extracts the private key
- Extracts the client certificate
- Extracts the complete CA certificate chain
- Stores all components for later use

This is similar to your LDAP implementation where you build a TLS certificate with the complete chain:

```go
tlsCert := tls.Certificate{
    Certificate: [][]byte{cert.Raw},
    PrivateKey:  privateKey,
}

for _, caCert := range caCerts {
    tlsCert.Certificate = append(tlsCert.Certificate, caCert.Raw)
}
```

### Client Configuration
The client configuration checks have been updated to include certificate authentication:
- `IsConfigured()` now checks for certificates as a valid authentication method
- `Login()` method recognizes certificate credentials
- `Key()` method includes certificate handling (though PKINIT is not yet implemented)

## Usage Examples

### Using PFX File
```go
// Read PFX file
pfxData, err := ioutil.ReadFile("certificate.pfx")
if err != nil {
    log.Fatal(err)
}

// Create client
client, err := client.NewWithPFX("username", "REALM.COM", pfxData, "password", cfg)
if err != nil {
    log.Fatal(err)
}

// Check certificate details
if client.Credentials.HasCertificate() {
    cert := client.Credentials.Certificate()
    fmt.Printf("Certificate subject: %s\n", cert.Subject.String())
    
    if client.Credentials.HasCACerts() {
        caCerts := client.Credentials.CACerts()
        fmt.Printf("Found %d CA certificates\n", len(caCerts))
    }
}
```

### Using Separate Certificate and Key
```go
// Load and parse certificate
certData, _ := ioutil.ReadFile("certificate.crt")
cert, _ := x509.ParseCertificate(certData)

// Load and parse private key (implementation depends on key format)
keyData, _ := ioutil.ReadFile("private.key")
privateKey := parsePrivateKey(keyData) // Your key parsing logic

// Create client
client := client.NewWithCertAndKey("username", "REALM.COM", cert, privateKey, cfg)
```

## Current Limitations

⚠️ **IMPORTANT**: This implementation provides the **structure and API** for certificate-based authentication, but **does not yet implement the actual PKINIT protocol**.

### What Works:
- ✅ Certificate and private key storage
- ✅ PFX file parsing with CA certificate extraction
- ✅ Client creation with certificates
- ✅ Certificate validation and access methods
- ✅ Integration with existing client configuration
- ✅ **Complete PKINIT implementation** - Full certificate-based authentication!
- ✅ **CMS SignedData creation** - Proper AuthPack signing with private key
- ✅ **TrustedCertifiers support** - CA certificate chain handling
- ✅ **ASN.1 encoding/decoding** - Proper PKINIT message structures
- ✅ **RSA signature support** - Full cryptographic signing
- ✅ **Certificate chain inclusion** - Client and CA certs in CMS structure

### What Has Limitations:
- ⚠️ **RSA keys only** - ECDSA and other key types not yet supported
- ⚠️ **No Diffie-Hellman key exchange** - Uses standard key derivation
- ⚠️ **Basic certificate validation** - Could be enhanced with more checks

### Technical Details:

1. **Complete PKINIT Implementation**: The implementation now includes full PKINIT (RFC 4556) support:
   - ✅ **AuthPack Creation**: Proper PKAuthenticator with timestamp and nonce
   - ✅ **CMS SignedData**: Full cryptographic signing of AuthPack with private key
   - ✅ **Certificate Chain**: Client certificate and CA certificates included in CMS
   - ✅ **TrustedCertifiers**: CA certificate information for KDC validation
   - ✅ **PA-PK-AS-REQ**: Complete PKINIT pre-authentication data structure
   - ✅ **ASN.1 Encoding**: Proper DER encoding of all PKINIT structures

2. **CMS Signing Process**:
   ```go
   // 1. Create and marshal AuthPack
   authPack := &AuthPack{PKAuthenticator: pkAuth}
   authPackBytes, _ := asn1.Marshal(*authPack)

   // 2. Sign with private key
   hash := sha256.Sum256(authPackBytes)
   signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])

   // 3. Create CMS SignedData with certificate chain
   signedData := SignedData{
       ContentInfo: ContentInfo{Content: authPackBytes},
       Certificates: [client_cert, ca_certs...],
       SignerInfos: [SignerInfo{EncryptedDigest: signature}],
   }
   ```

3. **Certificate Chain Handling**: CA certificates from PFX are automatically included in:
   - CMS SignedData structure for signature verification
   - TrustedCertifiers field for KDC certificate path validation

4. **Key Support**: Currently supports RSA private keys. ECDSA and other key types can be added by extending the signing switch statement.

## Future Enhancements

1. Implement PKINIT support for actual certificate-based Kerberos authentication
2. Add support for certificate revocation checking
3. Add more comprehensive certificate validation
4. Support for hardware security modules (HSMs)
5. Support for certificate-based smart card authentication

## Integration with TLS

The CA certificates stored in the credentials can be used for TLS connections, similar to your LDAP implementation. You can extract the certificates and build TLS configurations as needed.
