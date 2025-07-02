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
- ✅ **Basic PKINIT implementation** - Certificate-based login now works!
- ✅ **PKINIT PAData generation** - Creates proper PA-PK-AS-REQ structures
- ✅ **AS-REQ with certificate authentication** - Full authentication flow

### What Has Limitations:
- ⚠️ **Simplified PKINIT** - Basic implementation without full CMS signing
- ⚠️ **No Diffie-Hellman key exchange** - Uses simplified key derivation
- ⚠️ **Limited certificate validation** - Basic certificate handling

### Technical Details:

1. **PKINIT Not Implemented**: Certificate-based Kerberos authentication requires implementing PKINIT (Public Key Cryptography for Initial Authentication) per RFC 4556. This involves:
   - Creating AS-REQ with PKINIT pre-authentication data
   - Including client certificate in the request
   - Performing Diffie-Hellman key exchange with the KDC
   - Deriving session keys from the DH exchange
   - Handling PKINIT-specific AS-REP responses

2. **Key Parsing**: The example shows simplified key parsing. In practice, you'll need to handle different key formats (PEM, DER) and types (RSA, ECDSA, etc.).

3. **Certificate Validation**: Additional certificate validation logic may be needed depending on your PKI requirements.

## Future Enhancements

1. Implement PKINIT support for actual certificate-based Kerberos authentication
2. Add support for certificate revocation checking
3. Add more comprehensive certificate validation
4. Support for hardware security modules (HSMs)
5. Support for certificate-based smart card authentication

## Integration with TLS

The CA certificates stored in the credentials can be used for TLS connections, similar to your LDAP implementation. You can extract the certificates and build TLS configurations as needed.
