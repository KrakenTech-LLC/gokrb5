package main

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: cert_extensions <pfx_file> [password]")
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

	fmt.Printf("=== Certificate Extensions Analysis ===\n")
	fmt.Printf("Subject: %s\n", cert.Subject.String())
	fmt.Printf("Issuer: %s\n", cert.Issuer.String())

	fmt.Printf("\n=== All Extensions ===\n")
	for i, ext := range cert.Extensions {
		fmt.Printf("Extension %d:\n", i+1)
		fmt.Printf("  OID: %s\n", ext.Id.String())
		fmt.Printf("  Critical: %v\n", ext.Critical)
		fmt.Printf("  Length: %d bytes\n", len(ext.Value))
		fmt.Printf("  Raw Value (hex): %s\n", hex.EncodeToString(ext.Value))

		// Try to decode as string
		if isPrintableASCII(ext.Value) {
			fmt.Printf("  As ASCII: %q\n", string(ext.Value))
		}

		// Special handling for known extensions
		switch ext.Id.String() {
		case "2.5.29.17": // Subject Alternative Name
			fmt.Printf("  ** Subject Alternative Name Extension **\n")
			decodeSAN(ext.Value)
		case "1.3.6.1.4.1.311.25.2": // Microsoft Certificate Template
			fmt.Printf("  ** Microsoft Certificate Template **\n")
		case "1.3.6.1.5.2.2": // Kerberos Principal Name
			fmt.Printf("  ** Kerberos Principal Name Extension **\n")
		case "1.3.6.1.4.1.311.21.7": // Microsoft Certificate Template Information
			fmt.Printf("  ** Microsoft Certificate Template Information **\n")
		case "1.3.6.1.4.1.311.21.10": // Microsoft Application Policies
			fmt.Printf("  ** Microsoft Application Policies **\n")
		}
		fmt.Printf("\n")
	}

	fmt.Printf("=== DNS Names ===\n")
	for i, dns := range cert.DNSNames {
		fmt.Printf("  %d. %s\n", i+1, dns)
	}

	fmt.Printf("\n=== Email Addresses ===\n")
	for i, email := range cert.EmailAddresses {
		fmt.Printf("  %d. %s\n", i+1, email)
	}

	fmt.Printf("\n=== IP Addresses ===\n")
	for i, ip := range cert.IPAddresses {
		fmt.Printf("  %d. %s\n", i+1, ip.String())
	}

	fmt.Printf("\n=== URIs ===\n")
	for i, uri := range cert.URIs {
		fmt.Printf("  %d. %s\n", i+1, uri.String())
	}
}

func isPrintableASCII(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return len(data) > 0
}

func decodeSAN(data []byte) {
	// Try to decode the SAN extension
	var san asn1.RawValue
	_, err := asn1.Unmarshal(data, &san)
	if err != nil {
		fmt.Printf("    Failed to decode SAN: %v\n", err)
		return
	}

	// SAN is a sequence of GeneralNames
	var generalNames []asn1.RawValue
	_, err = asn1.Unmarshal(san.Bytes, &generalNames)
	if err != nil {
		fmt.Printf("    Failed to decode GeneralNames: %v\n", err)
		return
	}

	fmt.Printf("    Found %d GeneralName entries:\n", len(generalNames))
	for i, gn := range generalNames {
		fmt.Printf("    Entry %d:\n", i+1)
		fmt.Printf("      Tag: %d\n", gn.Tag)
		fmt.Printf("      Class: %d\n", gn.Class)
		fmt.Printf("      Length: %d\n", len(gn.Bytes))
		fmt.Printf("      Raw: %s\n", hex.EncodeToString(gn.Bytes))

		// Try to decode as string
		if isPrintableASCII(gn.Bytes) {
			fmt.Printf("      As String: %q\n", string(gn.Bytes))
		}

		// Check for UPN (tag 0, context-specific)
		if gn.Tag == 0 && gn.Class == asn1.ClassContextSpecific {
			fmt.Printf("      ** Possible UPN (otherName) **\n")
			// Try to decode the otherName structure
			decodeOtherName(gn.Bytes)
		}

		// Check for DNS name (tag 2, context-specific)
		if gn.Tag == 2 && gn.Class == asn1.ClassContextSpecific {
			fmt.Printf("      ** DNS Name: %s **\n", string(gn.Bytes))
		}

		// Check for email (tag 1, context-specific)
		if gn.Tag == 1 && gn.Class == asn1.ClassContextSpecific {
			fmt.Printf("      ** Email: %s **\n", string(gn.Bytes))
		}
	}
}

func decodeOtherName(data []byte) {
	// otherName is a sequence containing OID and value
	var otherName struct {
		TypeID asn1.ObjectIdentifier
		Value  asn1.RawValue `asn1:"explicit,tag:0"`
	}

	_, err := asn1.Unmarshal(data, &otherName)
	if err != nil {
		fmt.Printf("        Failed to decode otherName: %v\n", err)
		return
	}

	fmt.Printf("        OID: %s\n", otherName.TypeID.String())
	fmt.Printf("        Value: %s\n", hex.EncodeToString(otherName.Value.Bytes))

	// Check if it's a UPN (1.3.6.1.4.1.311.20.2.3)
	upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	if otherName.TypeID.Equal(upnOID) {
		fmt.Printf("        ** UPN Extension Found **\n")
		// The value should be a UTF8String
		var upnValue string
		_, err := asn1.Unmarshal(otherName.Value.Bytes, &upnValue)
		if err != nil {
			fmt.Printf("        Failed to decode UPN value: %v\n", err)
		} else {
			fmt.Printf("        UPN: %s\n", upnValue)
		}
	}
}
