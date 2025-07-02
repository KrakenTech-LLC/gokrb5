package main

import (
	"fmt"
	"log"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: cert_info <pfx_file> [password]")
		return
	}

	pfxPath := os.Args[1]
	pfxPassword := ""
	if len(os.Args) > 2 {
		pfxPassword = os.Args[2]
	}

	// Load PFX file
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		log.Fatalf("Failed to read PFX file: %v", err)
	}

	// Decode PFX
	_, cert, _, err := pkcs12.DecodeChain(pfxData, pfxPassword)
	if err != nil {
		log.Fatalf("Failed to decode PFX: %v", err)
	}

	fmt.Printf("=== Certificate Analysis ===\n")
	fmt.Printf("Subject: %s\n", cert.Subject.String())
	fmt.Printf("Issuer: %s\n", cert.Issuer.String())
	fmt.Printf("Serial Number: %s\n", cert.SerialNumber.String())
	fmt.Printf("Valid From: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Valid Until: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))

	fmt.Printf("\n=== Subject Details ===\n")
	fmt.Printf("Common Name: %s\n", cert.Subject.CommonName)
	fmt.Printf("Organization: %v\n", cert.Subject.Organization)
	fmt.Printf("Organizational Unit: %v\n", cert.Subject.OrganizationalUnit)
	fmt.Printf("Country: %v\n", cert.Subject.Country)
	fmt.Printf("Province: %v\n", cert.Subject.Province)
	fmt.Printf("Locality: %v\n", cert.Subject.Locality)

	fmt.Printf("\n=== Subject Alternative Names ===\n")
	fmt.Printf("DNS Names: %v\n", cert.DNSNames)
	fmt.Printf("Email Addresses: %v\n", cert.EmailAddresses)
	fmt.Printf("IP Addresses: %v\n", cert.IPAddresses)
	fmt.Printf("URIs: %v\n", cert.URIs)

	fmt.Printf("\n=== Key Usage ===\n")
	fmt.Printf("Key Usage: %v\n", cert.KeyUsage)
	fmt.Printf("Extended Key Usage: %v\n", cert.ExtKeyUsage)

	fmt.Printf("\n=== Possible Kerberos Principals ===\n")

	// Try to find Kerberos principal in various places
	principals := []string{}

	// Check DNS names for Kerberos format
	for _, dns := range cert.DNSNames {
		if strings.Contains(dns, "@") {
			principals = append(principals, dns)
		} else {
			// Try machine account format
			if strings.HasSuffix(dns, ".ankura.local") {
				machineName := strings.TrimSuffix(dns, ".ankura.local")
				principals = append(principals, machineName+"$@ANKURA.LOCAL")
			}
		}
	}

	// Check email addresses
	for _, email := range cert.EmailAddresses {
		if strings.Contains(email, "@") {
			principals = append(principals, email)
		}
	}

	// Check Common Name
	cn := cert.Subject.CommonName
	if cn != "" {
		if strings.Contains(cn, "@") {
			principals = append(principals, cn)
		} else {
			// Try as machine account
			if strings.HasSuffix(cn, "$") {
				principals = append(principals, cn+"@ANKURA.LOCAL")
			} else {
				principals = append(principals, cn+"@ANKURA.LOCAL")
				principals = append(principals, cn+"$@ANKURA.LOCAL")
			}
		}
	}

	if len(principals) > 0 {
		fmt.Printf("Suggested principals to try:\n")
		for i, principal := range principals {
			fmt.Printf("  %d. %s\n", i+1, principal)
		}
	} else {
		fmt.Printf("No obvious Kerberos principals found in certificate\n")
	}

	fmt.Printf("\n=== Extensions ===\n")
	for _, ext := range cert.Extensions {
		fmt.Printf("OID: %s, Critical: %v\n", ext.Id.String(), ext.Critical)
		if ext.Id.String() == "2.5.29.17" { // Subject Alternative Name
			fmt.Printf("  SAN Extension found, raw value: %x\n", ext.Value)
			// Try to decode as string
			if len(ext.Value) > 0 {
				fmt.Printf("  SAN as string: %q\n", string(ext.Value))
			}
		}
		if ext.Id.String() == "1.3.6.1.5.2.2" { // Kerberos Principal Name
			fmt.Printf("  Kerberos Principal Name Extension found: %x\n", ext.Value)
		}
		if ext.Id.String() == "1.3.6.1.4.1.311.25.2" { // Microsoft Certificate Template
			fmt.Printf("  Microsoft Certificate Template: %x\n", ext.Value)
		}
	}

	fmt.Printf("\n=== Troubleshooting Suggestions ===\n")
	fmt.Printf("The principal 'Odtestmach$@ANKURA.LOCAL' doesn't exist in the Kerberos database.\n")
	fmt.Printf("This could mean:\n")
	fmt.Printf("1. The computer account 'Odtestmach$' is not joined to the ANKURA.LOCAL domain\n")
	fmt.Printf("2. The computer account exists but is disabled\n")
	fmt.Printf("3. The computer account has a different name\n")
	fmt.Printf("4. PKINIT is not enabled for this account\n")
	fmt.Printf("\nTo resolve:\n")
	fmt.Printf("1. Check if the computer is domain-joined: 'nltest /dsgetdc:ANKURA.LOCAL'\n")
	fmt.Printf("2. Verify the computer account exists in Active Directory\n")
	fmt.Printf("3. Ensure PKINIT is enabled on the domain controller\n")
	fmt.Printf("4. Try using the computer's FQDN: 'host/odtestmach.ankura.local@ANKURA.LOCAL'\n")
}
