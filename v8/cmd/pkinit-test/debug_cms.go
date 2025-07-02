package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/KrakenTech-LLC/gokrb5/v8/pki"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: debug_cms <pfx_file>")
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
	privateKey, cert, caCerts, err := pkcs12.DecodeChain(pfxData, pfxPassword)
	if err != nil {
		log.Fatalf("Failed to decode PFX: %v", err)
	}

	fmt.Printf("=== PFX Analysis ===\n")
	fmt.Printf("Certificate: %s\n", cert.Subject.String())
	fmt.Printf("Issuer: %s\n", cert.Issuer.String())
	fmt.Printf("CA Certificates: %d\n", len(caCerts))
	for i, ca := range caCerts {
		fmt.Printf("  CA %d: %s\n", i+1, ca.Subject.String())
	}

	// Test CMS creation
	fmt.Printf("\n=== Testing CMS Creation ===\n")

	// Try to create CMS SignedData
	paData, err := pki.CreatePKINITPAData(cert, privateKey, 12345, caCerts)
	if err != nil {
		log.Fatalf("Failed to create PKINIT PAData: %v", err)
	}

	fmt.Printf("✅ Successfully created PKINIT PAData\n")
	fmt.Printf("PAData Type: %d\n", paData.PADataType)
	fmt.Printf("PAData Length: %d bytes\n", len(paData.PADataValue))
	fmt.Printf("PAData (hex): %s\n", hex.EncodeToString(paData.PADataValue[:min(64, len(paData.PADataValue))]))

	// Save the PAData for analysis
	err = os.WriteFile("pkinit_padata.bin", paData.PADataValue, 0644)
	if err != nil {
		log.Printf("Warning: Could not save PAData: %v", err)
	} else {
		fmt.Printf("✅ PAData saved to pkinit_padata.bin\n")
	}

	// Try to decode and analyze the PAData structure
	fmt.Printf("\n=== PAData Structure Analysis ===\n")
	analyzeASN1Structure(paData.PADataValue)

	fmt.Printf("\n=== Analysis Complete ===\n")
	fmt.Printf("The PAData structure was created successfully.\n")
	fmt.Printf("The issue is likely with the CMS SignedData format or KDC configuration.\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func analyzeASN1Structure(data []byte) {
	fmt.Printf("ASN.1 Structure Analysis:\n")
	if len(data) < 2 {
		fmt.Printf("  Data too short\n")
		return
	}

	fmt.Printf("  First few bytes: %02x %02x %02x %02x\n", data[0], data[1], data[2], data[3])

	// Check if it starts with SEQUENCE
	if data[0] == 0x30 {
		fmt.Printf("  ✅ Starts with SEQUENCE tag (0x30)\n")
	} else {
		fmt.Printf("  ❌ Does not start with SEQUENCE tag (got 0x%02x)\n", data[0])
	}

	// Try to parse length
	if len(data) > 1 {
		if data[1]&0x80 == 0 {
			fmt.Printf("  Length: %d (short form)\n", data[1])
		} else {
			lengthBytes := int(data[1] & 0x7f)
			if lengthBytes > 0 && len(data) > 1+lengthBytes {
				length := 0
				for i := 0; i < lengthBytes; i++ {
					length = (length << 8) | int(data[2+i])
				}
				fmt.Printf("  Length: %d (long form, %d bytes)\n", length, lengthBytes)
			}
		}
	}
}
