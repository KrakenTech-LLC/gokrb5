# Certificate Principal Extraction - Certipy Logic Implementation

This document describes the implementation of certipy-style certificate principal extraction logic in Go for the gokrb5 v8 library.

## Overview

The implementation mirrors the logic used in certipy for determining the correct Kerberos principal from a certificate file, including the same validation checks and fallback mechanisms, but without requiring user input.

## Key Functions

### 1. `ExtractPrincipalFromCertificateWithValidation(cert, providedUsername, providedDomain)`

This is the main function that implements the complete certipy logic:

```go
username, domain, err := pki.ExtractPrincipalFromCertificateWithValidation(cert, "", "")
```

**Features:**
- Extracts all possible identifications from the certificate
- Prioritizes identifications: UPN > Email > DNS > CN
- Validates provided username/domain against certificate identifications
- Handles machine account naming ($ suffixes)
- Handles subdomain relationships
- Returns lowercase username and domain

### 2. `getIdentificationsFromCertificate(cert)`

Extracts all possible identifications from a certificate:

```go
type CertificateIdentification struct {
    Type  string // "UPN", "DNS", "Email", "CN", etc.
    Value string
}
```

**Extraction Sources:**
- **UPN**: From Subject Alternative Name extension (most reliable for PKINIT)
- **DNS**: From SAN DNS names
- **Email**: From SAN email addresses  
- **CN**: From Subject Common Name
- **Other**: Additional subject components

### 3. `certIdToParts(identification)`

Converts certificate identifications to username/domain pairs:

- **UPN/Email**: `username@domain.com` → `username`, `domain.com`
- **DNS**: `hostname.domain.com` → `hostname`, `domain.com`
- **CN**: Various parsing strategies depending on format

## Validation Logic

### Username Validation

The function validates provided usernames against certificate identifications:

```go
func usernameMatches(provided, fromCert string) bool {
    // Direct match
    if provided == fromCert { return true }
    
    // Machine account handling
    if provided == fromCert+"$" { return true }
    if strings.HasSuffix(fromCert, "$") && provided == strings.TrimSuffix(fromCert, "$") {
        return true
    }
    
    return false
}
```

### Domain Validation

The function validates provided domains against certificate identifications:

```go
func domainMatches(provided, fromCert string) bool {
    // Direct match
    if provided == fromCert { return true }
    
    // Subdomain relationship
    // e.g., provided="example.com", fromCert="sub.example.com"
    providedWithDot := strings.TrimSuffix(provided, ".") + "."
    if strings.HasSuffix(fromCert, providedWithDot) { return true }
    
    return false
}
```

## Usage Examples

### Basic Usage (No Provided Credentials)

```go
username, domain, err := pki.ExtractPrincipalFromCertificateWithValidation(cert, "", "")
if err != nil {
    log.Fatalf("Failed to extract principal: %v", err)
}
upn := username + "@" + domain
```

### With Provided Credentials (Validation)

```go
username, domain, err := pki.ExtractPrincipalFromCertificateWithValidation(
    cert, 
    "john.doe",     // provided username
    "example.com",  // provided domain
)
if err != nil {
    log.Fatalf("Validation failed: %v", err)
}
```

### Backward Compatibility

```go
// Simple extraction (old interface)
upn := pki.ExtractPrincipalFromCertificateSimple(cert)
```

## Error Handling

The function returns specific errors that mirror certipy's behavior:

- `"could not find identification in the provided certificate"`
- `"username or domain is not specified, and identification information was not found in the certificate"`
- `"the provided username does not match the identification found in the provided certificate"`
- `"the provided domain does not match the identification found in the provided certificate"`
- `"username or domain is invalid"`

## Additional Features

### Object SID Extraction

```go
objectSID := pki.GetObjectSIDFromCertificate(cert)
```

Extracts the Windows object SID from certificate extensions (OID 1.3.6.1.4.1.311.25.2).

### Certificate Information

```go
info := pki.GetCertificateInfo(cert)
// Returns comprehensive certificate details including:
// - All identifications found
// - Extracted principal information
// - Validation status
// - Object SID (if present)
```

### PKINIT Validation

```go
err := pki.ValidateCertificateForPKINIT(cert)
// Validates certificate is suitable for PKINIT authentication
```

## Differences from Certipy

1. **No User Input**: Instead of prompting for selection when multiple identifications are found, the implementation uses a priority system (UPN > Email > DNS > CN).

2. **Automatic Selection**: The function automatically selects the best identification based on type priority.

3. **Error Returns**: Instead of prompting for continuation on validation failures, the function returns descriptive errors.

4. **Go Conventions**: Function names and return patterns follow Go conventions.

## Integration with PKINIT

This implementation is designed to work seamlessly with the existing PKINIT authentication code:

```go
// Extract principal from certificate
username, domain, err := pki.ExtractPrincipalFromCertificateWithValidation(cert, "", "")
if err != nil {
    return err
}

// Use in PKINIT authentication
upn := username + "@" + domain
// ... proceed with PKINIT authentication using the extracted UPN
```

## Testing

The implementation includes comprehensive examples and test scenarios in `certificate_principal_example.go` that demonstrate:

- Multiple identification types
- Validation scenarios
- Error conditions
- Machine account handling
- Domain relationship validation

This ensures compatibility with various certificate formats and use cases encountered in real-world PKINIT deployments.
