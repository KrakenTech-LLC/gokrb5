package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"github.com/KrakenTech-LLC/gokrb5/v8/client"
	"github.com/KrakenTech-LLC/gokrb5/v8/config"
	"github.com/KrakenTech-LLC/gokrb5/v8/credentials"
	"golang.org/x/term"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
)

func main() {
	fmt.Println("=== PKINIT Authentication Test ===")
	fmt.Println("This program tests certificate-based Kerberos authentication")
	fmt.Println()

	// Get user inputs
	pfxPath := promptForInput("Enter PFX file path: ")
	pfxPassword := promptForPassword("Enter PFX password (press Enter if none): ")
	username := promptForInput("Enter username: ")
	realm := promptForInput("Enter Kerberos realm (e.g., EXAMPLE.COM): ")
	kdc := promptForInput("Enter KDC address (e.g., kdc.example.com:88): ")

	fmt.Println()
	fmt.Println("=== Configuration ===")
	fmt.Printf("PFX File: %s\n", pfxPath)
	fmt.Printf("Username: %s\n", username)
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

	startTime := time.Now()
	err = client.Login()
	duration := time.Since(startTime)

	if err != nil {
		fmt.Printf("❌ PKINIT authentication failed after %v\n", duration)
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

func promptForInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func promptForPassword(prompt string) string {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password: %v", err)
	}
	fmt.Println() // New line after password input
	return string(password)
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
