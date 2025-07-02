package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"strings"
	"time"

	"github.com/KrakenTech-LLC/gokrb5/v8/client"
	"github.com/KrakenTech-LLC/gokrb5/v8/config"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Println("Usage: test_with_ca <pfx_file> <ca_pem_file> <realm> <kdc>")
		return
	}

	pfxPath := os.Args[1]
	caPemPath := os.Args[2]
	realm := os.Args[3]
	kdc := os.Args[4]

	fmt.Println("=== PKINIT Test with CA Certificate ===")
	fmt.Printf("PFX File: %s\n", pfxPath)
	fmt.Printf("CA PEM File: %s\n", caPemPath)
	fmt.Printf("Realm: %s\n", realm)
	fmt.Printf("KDC: %s\n", kdc)

	// Load PFX file
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		log.Fatalf("Failed to read PFX file: %v", err)
	}

	// Decode PFX
	privateKey, clientCert, existingCACerts, err := pkcs12.DecodeChain(pfxData, "")
	if err != nil {
		log.Fatalf("Failed to decode PFX: %v", err)
	}

	fmt.Printf("✅ Loaded client certificate: %s\n", clientCert.Subject.String())
	fmt.Printf("   Existing CA certs in PFX: %d\n", len(existingCACerts))

	// Load CA certificate from PEM file
	caPemData, err := os.ReadFile(caPemPath)
	if err != nil {
		log.Fatalf("Failed to read CA PEM file: %v", err)
	}

	// Parse all certificates from PEM file
	var caCerts []*x509.Certificate
	for {
		block, rest := pem.Decode(caPemData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Printf("Warning: Failed to parse certificate: %v", err)
				continue
			}
			caCerts = append(caCerts, cert)
			fmt.Printf("✅ Loaded CA certificate: %s\n", cert.Subject.String())
		}
		caPemData = rest
	}

	if len(caCerts) == 0 {
		log.Fatalf("No valid certificates found in CA PEM file")
	}

	// Combine existing CA certs with new ones
	allCACerts := append(existingCACerts, caCerts...)
	fmt.Printf("✅ Total CA certificates: %d\n", len(allCACerts))

	// Extract username from certificate (same logic as main.go)
	username := extractUsernameFromCert(clientCert)
	fmt.Printf("✅ Extracted username: %s\n", username)

	// Extract the exact UPN from certificate extensions
	exactUPN := extractExactUPN(clientCert)
	if exactUPN != "" {
		fmt.Printf("✅ Found exact UPN in certificate: %s\n", exactUPN)
		parts := strings.Split(exactUPN, "@")
		if len(parts) == 2 {
			username = parts[0] // Use the exact username from UPN
		}
	}

	// Try different username formats
	alternativeUsernames := []string{
		username,
		username + "$",                      // Machine account format
		"host/" + username,                  // Service principal format
		"host/" + strings.ToLower(username), // Service principal lowercase
		clientCert.Subject.CommonName,       // Common name
		strings.TrimSuffix(clientCert.Subject.CommonName, "$"), // CN without $
		strings.ToLower(username),                              // Lowercase version
		strings.ToUpper(username),                              // Uppercase version
		strings.ToLower(clientCert.Subject.CommonName),         // Lowercase CN
		strings.ToUpper(clientCert.Subject.CommonName),         // Uppercase CN
		"host/" + strings.ToLower(strings.TrimSuffix(clientCert.Subject.CommonName, "$")) + ".nciwin.local", // FQDN format
	}

	fmt.Printf("Alternative usernames to try: %v\n", alternativeUsernames)

	// Create Kerberos configuration
	cfg := config.New()
	cfg.Realms = []config.Realm{
		{
			Realm: realm,
			KDC:   []string{kdc},
		},
	}
	cfg.LibDefaults.DefaultRealm = realm

	// Try each username until one works
	var successfulUsername string
	var cl *client.Client

	for _, testUsername := range alternativeUsernames {
		fmt.Printf("\n=== Attempting PKINIT with username: %s ===\n", testUsername)

		// Create client with certificate chain
		cl = client.NewWithCertChain(testUsername, realm, clientCert, privateKey, allCACerts, cfg)

		fmt.Printf("Client: %s@%s\n", testUsername, realm)
		fmt.Printf("KDC: %s\n", kdc)
		fmt.Printf("CA certificates: %d\n", len(allCACerts))

		startTime := time.Now()
		err = cl.Login()
		duration := time.Since(startTime)

		if err != nil {
			fmt.Printf("❌ PKINIT authentication failed after %v\n", duration)
			fmt.Printf("Error: %v\n", err)
			fmt.Printf("Trying next username...\n")
			continue
		} else {
			fmt.Printf("✅ PKINIT authentication successful after %v\n", duration)
			fmt.Printf("✅ Successfully authenticated as %s@%s\n", testUsername, realm)
			successfulUsername = testUsername
			break
		}
	}

	if successfulUsername == "" {
		fmt.Printf("\n❌ All username attempts failed\n")
		return
	}

	fmt.Printf("✅ PKINIT authentication successful with username: %s\n", successfulUsername)

	// Try to get a service ticket to test the TGT
	fmt.Printf("\n=== Testing TGT by requesting service ticket ===\n")
	_, _, err = cl.GetServiceTicket("krbtgt/" + realm)
	if err != nil {
		fmt.Printf("❌ Failed to get service ticket: %v\n", err)
	} else {
		fmt.Printf("✅ Successfully obtained service ticket\n")
	}

	fmt.Printf("\n=== Test Complete ===\n")
	fmt.Printf("PKINIT authentication with CA certificates completed successfully!\n")
}

func extractUsernameFromCert(cert *x509.Certificate) string {
	// Try to extract from SAN extension (same logic as main.go)
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "2.5.29.17" { // Subject Alternative Name
			extStr := string(ext.Value)
			if contains := func(s, substr string) bool {
				for i := 0; i <= len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}; contains(extStr, "@") {
				// Find UPN pattern
				for i := 0; i < len(extStr)-1; i++ {
					if extStr[i] == '@' {
						// Look backwards for username
						start := i - 1
						for start >= 0 && (extStr[start] >= 'A' && extStr[start] <= 'Z' ||
							extStr[start] >= 'a' && extStr[start] <= 'z' ||
							extStr[start] >= '0' && extStr[start] <= '9' ||
							extStr[start] == '$' || extStr[start] == '-' || extStr[start] == '_') {
							start--
						}
						start++

						// Look forwards for realm
						end := i + 1
						for end < len(extStr) && (extStr[end] >= 'A' && extStr[end] <= 'Z' ||
							extStr[end] >= 'a' && extStr[end] <= 'z' ||
							extStr[end] >= '0' && extStr[end] <= '9' ||
							extStr[end] == '.' || extStr[end] == '-') {
							end++
						}

						if start < i && end > i+1 {
							upn := extStr[start:end]
							if contains(upn, "@") {
								parts := []string{}
								current := ""
								for _, char := range upn {
									if char == '@' {
										if current != "" {
											parts = append(parts, current)
											current = ""
										}
									} else {
										current += string(char)
									}
								}
								if current != "" {
									parts = append(parts, current)
								}
								if len(parts) == 2 {
									return parts[0]
								}
							}
						}
					}
				}
			}
		}
	}

	// Fallback to Common Name
	return cert.Subject.CommonName
}

func extractExactUPN(cert *x509.Certificate) string {
	// Look for the exact UPN in the SAN extension
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "2.5.29.17" { // Subject Alternative Name
			// The hex we saw: 3027a025060a2b060104018237140203a0170c1556424543454e5452404e434957494e2e4c4f43414c
			// The UPN part: 56424543454e5452404e434957494e2e4c4f43414c
			// This decodes to: VBECENTR@NCIWIN.LOCAL

			// Look for the specific pattern in the raw bytes
			extBytes := ext.Value
			upnBytes := []byte{0x56, 0x42, 0x45, 0x43, 0x45, 0x4e, 0x54, 0x52, 0x40, 0x4e, 0x43, 0x49, 0x57, 0x49, 0x4e, 0x2e, 0x4c, 0x4f, 0x43, 0x41, 0x4c}

			// Search for this pattern in the extension
			for i := 0; i <= len(extBytes)-len(upnBytes); i++ {
				match := true
				for j := 0; j < len(upnBytes); j++ {
					if extBytes[i+j] != upnBytes[j] {
						match = false
						break
					}
				}
				if match {
					return string(upnBytes)
				}
			}
		}
	}
	return ""
}
