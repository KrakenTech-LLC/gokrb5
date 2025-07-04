package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/KrakenTech-LLC/gokrb5/v8/client"
	"github.com/KrakenTech-LLC/gokrb5/v8/config"
	"github.com/KrakenTech-LLC/gokrb5/v8/credentials"
	"github.com/KrakenTech-LLC/gokrb5/v8/pki"
	"log"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"strings"
	"time"
)

func main() {

	var (
		pfxPath     string
		pfxPassword string
		realm       string
		kdc         string
	)

	if len(os.Args[1:]) < 3 {
		fmt.Println("Usage: pkinit <pfx_file_path> <pfx_password> <realm> <kdc>")
		return
	} else if len(os.Args[1:]) == 4 {
		pfxPath = os.Args[1]
		pfxPassword = os.Args[2]
		realm = os.Args[3]
		kdc = os.Args[4]
	} else if len(os.Args[1:]) == 3 {
		pfxPath = os.Args[1]
		realm = os.Args[2]
		kdc = os.Args[3]
	} else {
		fmt.Println("Usage: pkinit <pfx_file_path> <pfx_password> <realm> <kdc>")
		return
	}

	if len(os.Args[1:]) == 4 {
		pfxPath = os.Args[1]
		pfxPassword = os.Args[2]
		realm = os.Args[3]
		kdc = os.Args[4]
	} else if len(os.Args[1:]) == 3 {
		pfxPath = os.Args[1]
		realm = os.Args[2]
		kdc = os.Args[3]
	}

	fmt.Println("=== PKINIT Authentication Test ===")
	fmt.Println("Test certificate-based Kerberos authentication")
	fmt.Println()

	fmt.Println()
	fmt.Println("=== Configuration ===")
	fmt.Printf("PFX File: %s\n", pfxPath)
	fmt.Printf("Realm: %s\n", realm)
	fmt.Printf("KDC: %s\n", kdc)
	fmt.Println()

	// Load PFX file
	fmt.Println("=== Loading PFX File ===")
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		log.Fatalf("Failed to read PFX file: %v", err)
	}
	fmt.Printf("✅ Successfully loaded PFX file (%d bytes)\n", len(pfxData))

	// Extract certificate to get username
	fmt.Println("\n=== Extracting Certificate Information ===")
	username, err := extractUsernameFromPFX(pfxData, pfxPassword)
	if err != nil {
		log.Fatalf("Failed to extract username from certificate: %v", err)
	}
	fmt.Printf("✅ Extracted username from certificate: %s\n", username)

	// Create Kerberos configuration
	fmt.Println("\n=== Creating Kerberos Configuration ===")
	krb5Config := createKerberosConfig(realm, kdc)
	fmt.Printf("✅ Created Kerberos configuration for realm %s\n", realm)
	fmt.Printf("   Default realm: %s\n", krb5Config.LibDefaults.DefaultRealm)
	fmt.Printf("   KDC: %s\n", kdc)

	// Create client with PFX
	fmt.Println("\n=== Creating PKINIT Client ===")
	client, err := client.NewWithPFX(username, realm, pfxData, pfxPassword, krb5Config)
	if err != nil {
		log.Fatalf("Failed to create client with PFX: %v", err)
	}
	fmt.Printf("✅ Successfully created client for user: %s@%s\n", client.Credentials.UserName(), client.Credentials.Domain())

	// Display certificate information
	displayCertificateInfo(client.Credentials)

	// Check client configuration
	fmt.Println("\n=== Validating Client Configuration ===")
	if configured, err := client.IsConfigured(); !configured {
		log.Fatalf("Client configuration error: %v", err)
	}
	fmt.Println("✅ Client is properly configured")

	// Enable verbose logging
	fmt.Println("\n=== Enabling Verbose Logging ===")
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	fmt.Println("✅ Verbose logging enabled")

	// Attempt PKINIT authentication
	fmt.Println("\n=== Attempting PKINIT Authentication ===")
	fmt.Println("Connecting to KDC and performing certificate-based authentication...")

	// Add debug information
	fmt.Printf("Debug: Certificate has CA certs: %v\n", client.Credentials.HasCACerts())
	if client.Credentials.HasCACerts() {
		fmt.Printf("Debug: Number of CA certs: %d\n", len(client.Credentials.CACerts()))
	}

	startTime := time.Now()
	err = client.Login()
	duration := time.Since(startTime)

	if err != nil {
		fmt.Printf("❌ PKINIT authentication failed after %v\n", duration)
		fmt.Printf("Debug: Full error details: %+v\n", err)
		log.Fatalf("Authentication error: %v", err)
	}

	fmt.Printf("✅ PKINIT authentication successful! (took %v)\n", duration)
	fmt.Println("   Certificate-based Kerberos authentication completed")

	// Display session information
	displaySessionInfo(client)

	// Extract and save TGT
	fmt.Println("\n=== Extracting TGT ===")
	err = extractAndSaveTGT(client, username, realm)
	if err != nil {
		log.Printf("Warning: Failed to extract TGT: %v", err)
	} else {
		fmt.Println("✅ TGT successfully extracted and saved")
	}

	// Test service ticket acquisition
	fmt.Println("\n=== Testing Service Ticket Acquisition ===")
	testServiceTicket(client, realm)

	fmt.Println("\n=== Test Complete ===")
	fmt.Println("PKINIT authentication test completed successfully!")
}

// saveASReqForDebugging saves the AS-REQ message for debugging purposes
func saveASReqForDebugging(asReqBytes []byte, filename string) {
	// Save raw bytes
	err := os.WriteFile(filename+".bin", asReqBytes, 0644)
	if err != nil {
		log.Printf("Warning: Could not save AS-REQ binary: %v", err)
		return
	}

	// Save hex dump
	hexDump := hex.Dump(asReqBytes)
	err = os.WriteFile(filename+".hex", []byte(hexDump), 0644)
	if err != nil {
		log.Printf("Warning: Could not save AS-REQ hex dump: %v", err)
		return
	}

	// Save base64
	b64 := base64.StdEncoding.EncodeToString(asReqBytes)
	err = os.WriteFile(filename+".b64", []byte(b64), 0644)
	if err != nil {
		log.Printf("Warning: Could not save AS-REQ base64: %v", err)
		return
	}

	fmt.Printf("Debug: AS-REQ saved to %s.{bin,hex,b64} (%d bytes)\n", filename, len(asReqBytes))
}

// Note: Principal extraction functions are now in the pki package

// extractUsernameFromPFX extracts the Kerberos principal name from a PFX certificate
func extractUsernameFromPFX(pfxData []byte, password string) (string, error) {
	// Decode the PFX to get the certificate
	_, cert, caCerts, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return "", fmt.Errorf("failed to decode PFX: %v", err)
	}

	if cert == nil {
		return "", fmt.Errorf("no certificate found in PFX")
	}

	// Debug: Show what we found in the PFX
	fmt.Printf("   Debug: PFX contains %d CA certificates\n", len(caCerts))
	for i, caCert := range caCerts {
		fmt.Printf("   Debug: CA %d: %s\n", i+1, caCert.Subject.String())
	}

	// Extract the principal using the pki package function
	principal := pki.ExtractPrincipalFromCertificate(cert)
	if principal != "" {
		fmt.Printf("   Found principal in certificate: %s\n", principal)
		return principal, nil
	}

	return "", fmt.Errorf("no valid principal found in certificate")

	// Try to extract username from Subject Alternative Names (SAN)
	for _, name := range cert.DNSNames {
		// Look for Kerberos principal format: user@REALM
		if strings.Contains(name, "@") {
			parts := strings.Split(name, "@")
			if len(parts) == 2 {
				fmt.Printf("   Found Kerberos principal in SAN DNS: %s\n", name)
				return parts[0], nil // Return just the username part
			}
		}
	}

	// Try to extract from Subject Alternative Names (other names)
	for _, email := range cert.EmailAddresses {
		if strings.Contains(email, "@") {
			parts := strings.Split(email, "@")
			if len(parts) == 2 {
				fmt.Printf("   Found potential principal in SAN email: %s\n", email)
				return parts[0], nil
			}
		}
	}

	// Try to extract from SAN extension (Microsoft UPN)
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "2.5.29.17" { // Subject Alternative Name
			// Look for UPN in the raw extension data
			extStr := string(ext.Value)
			if strings.Contains(extStr, "@") {
				// Find the UPN pattern
				for i := 0; i < len(extStr)-1; i++ {
					if extStr[i] == '@' {
						// Look backwards for the start of the username
						start := i - 1
						for start >= 0 && (extStr[start] >= 'A' && extStr[start] <= 'Z' ||
							extStr[start] >= 'a' && extStr[start] <= 'z' ||
							extStr[start] >= '0' && extStr[start] <= '9' ||
							extStr[start] == '$' || extStr[start] == '-' || extStr[start] == '_') {
							start--
						}
						start++

						// Look forwards for the end of the realm
						end := i + 1
						for end < len(extStr) && (extStr[end] >= 'A' && extStr[end] <= 'Z' ||
							extStr[end] >= 'a' && extStr[end] <= 'z' ||
							extStr[end] >= '0' && extStr[end] <= '9' ||
							extStr[end] == '.' || extStr[end] == '-') {
							end++
						}

						if start < i && end > i+1 {
							upn := extStr[start:end]
							if strings.Contains(upn, "@") {
								parts := strings.Split(upn, "@")
								if len(parts) == 2 {
									fmt.Printf("   Found UPN in SAN extension: %s\n", upn)
									return parts[0], nil
								}
							}
						}
					}
				}
			}
		}
	}

	// Try to extract from Subject DN Common Name
	if cert.Subject.CommonName != "" {
		cn := cert.Subject.CommonName
		fmt.Printf("   Found Common Name: %s\n", cn)

		// If CN contains @, split it
		if strings.Contains(cn, "@") {
			parts := strings.Split(cn, "@")
			if len(parts) == 2 {
				fmt.Printf("   Extracted username from CN: %s\n", parts[0])
				return parts[0], nil
			}
		}

		// Otherwise use the whole CN as username
		fmt.Printf("   Using full CN as username: %s\n", cn)
		return cn, nil
	}

	// If all else fails, try the first part of the first organizational unit
	if len(cert.Subject.OrganizationalUnit) > 0 {
		ou := cert.Subject.OrganizationalUnit[0]
		fmt.Printf("   Using first OU as username: %s\n", ou)
		return ou, nil
	}

	return "", fmt.Errorf("could not extract username from certificate - no suitable field found")
}

func createKerberosConfig(realm, kdc string) *config.Config {
	// Create a basic Kerberos configuration
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DNSLookupRealm = false
	cfg.LibDefaults.DNSLookupKDC = false

	// Add realm configuration
	cfg.Realms = []config.Realm{
		{
			Realm:         realm,
			KDC:           []string{kdc},
			AdminServer:   []string{kdc},
			DefaultDomain: strings.ToLower(realm),
			KPasswdServer: []string{kdc},
		},
	}

	return cfg
}

func displayCertificateInfo(creds *credentials.Credentials) {
	fmt.Println("\n=== Certificate Information ===")

	if !creds.HasCertificate() {
		fmt.Println("❌ No certificate found in credentials")
		return
	}

	cert := creds.Certificate()
	fmt.Printf("✅ Client Certificate:\n")
	fmt.Printf("   Subject: %s\n", cert.Subject.String())
	fmt.Printf("   Issuer: %s\n", cert.Issuer.String())
	fmt.Printf("   Serial Number: %s\n", cert.SerialNumber.String())
	fmt.Printf("   Valid From: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("   Valid Until: %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("   Key Usage: %v\n", cert.KeyUsage)

	if creds.HasCACerts() {
		caCerts := creds.CACerts()
		fmt.Printf("✅ CA Certificates (%d found):\n", len(caCerts))
		for i, caCert := range caCerts {
			fmt.Printf("   CA %d: %s\n", i+1, caCert.Subject.String())
		}
	} else {
		fmt.Println("  No CA certificates found")
	}
}

func displaySessionInfo(cl *client.Client) {
	fmt.Println("\n=== Session Information ===")

	// Try to get session information using the correct method
	realm := cl.Credentials.Domain()

	// Get TGT and session key
	tgt, sessionKey, err := cl.GetTGT(realm)
	if err != nil {
		fmt.Printf("  Could not retrieve TGT: %v\n", err)
		return
	}

	fmt.Printf("✅ Active Kerberos Session:\n")
	fmt.Printf("   TGT Realm: %s\n", tgt.Realm)
	fmt.Printf("   TGT Server: %s\n", tgt.SName.PrincipalNameString())
	fmt.Printf("   Session Key Type: %d\n", sessionKey.KeyType)
	fmt.Printf("   Session Key Length: %d bytes\n", len(sessionKey.KeyValue))

	// Try to get session times - this is an internal method, so we'll handle it gracefully
	fmt.Printf("   TGT Retrieved Successfully: ✅\n")
}

func extractAndSaveTGT(cl *client.Client, username, realm string) error {
	fmt.Println("Extracting TGT from client session...")

	// Get the TGT and session key
	tgt, sessionKey, err := cl.GetTGT(realm)
	if err != nil {
		return fmt.Errorf("failed to get TGT: %v", err)
	}

	// Create output filename
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("tgt_%s_%s_%s.b64", username, realm, timestamp)

	fmt.Printf("Saving TGT to file: %s\n", filename)

	// Create TGT file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create TGT file: %v", err)
	}
	defer file.Close()

	// Marshal the TGT ticket to bytes
	tgtBytes, err := tgt.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal TGT: %v", err)
	}

	// Write TGT information and data
	tgtInfo := fmt.Sprintf("TGT Information for %s@%s\n", username, realm)
	tgtInfo += fmt.Sprintf("Extraction Time: %s\n", time.Now().Format(time.RFC3339))
	tgtInfo += fmt.Sprintf("TGT Realm: %s\n", tgt.Realm)
	tgtInfo += fmt.Sprintf("TGT Server: %s\n", tgt.SName.PrincipalNameString())
	tgtInfo += fmt.Sprintf("Session Key Type: %d\n", sessionKey.KeyType)
	tgtInfo += fmt.Sprintf("Session Key Length: %d bytes\n", len(sessionKey.KeyValue))
	tgtInfo += fmt.Sprintf("Session Key (base64): %s\n", base64.StdEncoding.EncodeToString(sessionKey.KeyValue))
	tgtInfo += fmt.Sprintf("TGT Size: %d bytes\n", len(tgtBytes))
	tgtInfo += fmt.Sprintf("TGT (base64): %s\n", base64.StdEncoding.EncodeToString(tgtBytes))

	_, err = file.WriteString(tgtInfo)
	if err != nil {
		return fmt.Errorf("failed to write TGT information: %v", err)
	}

	fmt.Printf("✅ TGT extracted and saved to: %s\n", filename)
	fmt.Printf("   TGT Size: %d bytes\n", len(tgtBytes))
	fmt.Printf("   Session Key Type: %d\n", sessionKey.KeyType)
	return nil
}

func testServiceTicket(cl *client.Client, realm string) {
	fmt.Println("Testing service ticket acquisition...")

	// Try to get a service ticket for a common service
	serviceName := fmt.Sprintf("krbtgt/%s", realm)
	fmt.Printf("Attempting to get service ticket for: %s\n", serviceName)

	ticket, key, err := cl.GetServiceTicket(serviceName)
	if err != nil {
		fmt.Printf("  Service ticket acquisition failed: %v\n", err)
		return
	}

	fmt.Printf("✅ Service ticket acquired successfully!\n")
	fmt.Printf("   Service: %s\n", serviceName)

	// Marshal ticket to get its size
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		fmt.Printf("   Ticket size: Unable to determine (%v)\n", err)
	} else {
		fmt.Printf("   Ticket size: %d bytes\n", len(ticketBytes))
	}
	fmt.Printf("   Session key type: %d\n", key.KeyType)
}
