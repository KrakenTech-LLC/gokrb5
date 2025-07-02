package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/KrakenTech-LLC/gokrb5/v8/client"
	"github.com/KrakenTech-LLC/gokrb5/v8/config"
)

func main() {
	// Example 1: Creating a client with PFX file
	fmt.Println("Example 1: Creating client with PFX file")

	// Load PFX file
	pfxData, err := os.ReadFile("path/to/certificate.pfx")
	if err != nil {
		log.Printf("Error reading PFX file: %v", err)
		// Continue with other examples
	} else {
		// Load Kerberos configuration
		cfg, err := config.Load("path/to/krb5.conf")
		if err != nil {
			log.Printf("Error loading krb5 config: %v", err)
		} else {
			// Create client with PFX
			client, err := client.NewWithPFX("username", "REALM.COM", pfxData, "pfx_password", cfg)
			if err != nil {
				log.Printf("Error creating client with PFX: %v", err)
			} else {
				fmt.Printf("Successfully created client with PFX for user: %s\n", client.Credentials.UserName())

				// Check certificate details
				if client.Credentials.HasCertificate() {
					cert := client.Credentials.Certificate()
					fmt.Printf("Certificate subject: %s\n", cert.Subject.String())

					if client.Credentials.HasCACerts() {
						caCerts := client.Credentials.CACerts()
						fmt.Printf("Found %d CA certificates in the chain\n", len(caCerts))
						for i, caCert := range caCerts {
							fmt.Printf("  CA %d: %s\n", i+1, caCert.Subject.String())
						}
					}
				}

				// Check if client is configured
				if configured, err := client.IsConfigured(); configured {
					fmt.Println("Client is properly configured")
				} else {
					log.Printf("Client configuration error: %v", err)
				}
			}
		}
	}

	fmt.Println("\nExample 2: Creating client with separate certificate and key")

	// Load certificate file
	certData, err := os.ReadFile("path/to/certificate.crt")
	if err != nil {
		log.Printf("Error reading certificate file: %v", err)
		return
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		log.Printf("Error parsing certificate: %v", err)
		return
	}

	// Load private key file (this is a simplified example - in practice you'd need to handle different key formats)
	keyData, err := os.ReadFile("path/to/private.key")
	if err != nil {
		log.Printf("Error reading private key file: %v", err)
		return
	}

	// Parse private key (this would need proper implementation based on key type)
	// For demonstration purposes, we'll use nil
	var privateKey interface{} = keyData // In practice, parse this properly

	// Load Kerberos configuration
	cfg, err := config.Load("path/to/krb5.conf")
	if err != nil {
		log.Printf("Error loading krb5 config: %v", err)
		return
	}

	// Create client with certificate and key
	_client := client.NewWithCertAndKey("username", "REALM.COM", cert, privateKey, cfg)
	fmt.Printf("Successfully created client with certificate for user: %s\n", client.Credentials.UserName())

	// Check if client has certificate
	if _client.Credentials.HasCertificate() {
		fmt.Println("Client has certificate credentials")
		fmt.Printf("Certificate subject: %s\n", cert.Subject.String())
	}

	// Check if client is configured
	if configured, err := _client.IsConfigured(); configured {
		fmt.Println("Client is properly configured")
	} else {
		log.Printf("Client configuration error: %v", err)
	}

	fmt.Println("\nExample 3: Creating client with certificate chain")

	// This example shows how to use NewWithCertChain when you have separate CA certificates
	// Load CA certificates (this is a simplified example)
	caCertData, err := ioutil.ReadFile("path/to/ca-cert.crt")
	if err != nil {
		log.Printf("Error reading CA certificate file: %v", err)
	} else {
		// Parse CA certificate
		caCert, err := x509.ParseCertificate(caCertData)
		if err != nil {
			log.Printf("Error parsing CA certificate: %v", err)
		} else {
			// Create client with certificate chain
			caCerts := []*x509.Certificate{caCert}
			_client := client.NewWithCertChain("username", "REALM.COM", cert, privateKey, caCerts, cfg)
			fmt.Printf("Successfully created client with certificate chain for user: %s\n", client.Credentials.UserName())

			if _client.Credentials.HasCACerts() {
				fmt.Printf("Client has %d CA certificates\n", len(_client.Credentials.CACerts()))
			}
		}
	}

	// Important: Demonstrate current limitations
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("IMPORTANT: Current Implementation Status")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("✅ Certificate storage and management: WORKING")
	fmt.Println("✅ PFX parsing with CA certificates: WORKING")
	fmt.Println("✅ Client creation with certificates: WORKING")
	fmt.Println("❌ Actual certificate-based login: NOT IMPLEMENTED")
	fmt.Println("")
	fmt.Println("The Login() method will return an error for certificate-based clients")
	fmt.Println("because PKINIT (RFC 4556) is not yet implemented.")
	fmt.Println("")
	fmt.Println("This implementation provides the foundation and API structure")
	fmt.Println("for when PKINIT support is added in the future.")

	// Demonstrate what happens if you try to login with certificates
	fmt.Println("\nTo demonstrate the current limitation, here's what happens")
	fmt.Println("when you try to login with a certificate-based client:")
	fmt.Println("client.Login() would return:")
	fmt.Println("\"PKINIT (certificate-based authentication) is not yet implemented...\"")
	fmt.Println("")
	fmt.Println("The certificate data is properly stored and accessible,")
	fmt.Println("but the actual Kerberos authentication requires PKINIT implementation.")
}
