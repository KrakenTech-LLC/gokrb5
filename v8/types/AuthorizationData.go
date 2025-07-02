package types

import (
	"github.com/jcmturner/gofork/encoding/asn1"
)

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.2.6

// AuthorizationData implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6
type AuthorizationData []AuthorizationDataEntry

// AuthorizationDataEntry implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6
type AuthorizationDataEntry struct {
	ADType int32  `asn1:"explicit,tag:0" json:"ad_type"`
	ADData []byte `asn1:"explicit,tag:1" json:"ad_data"`
}

// ADIfRelevant implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6.1
type ADIfRelevant AuthorizationData

// ADKDCIssued implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6.2
type ADKDCIssued struct {
	ADChecksum Checksum          `asn1:"explicit,tag:0" json:"ad_checksum"`
	IRealm     string            `asn1:"optional,generalstring,explicit,tag:1" json:"i_realm"`
	Isname     PrincipalName     `asn1:"optional,explicit,tag:2" json:"isname"`
	Elements   AuthorizationData `asn1:"explicit,tag:3" json:"elements"`
}

// ADAndOr implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6.3
type ADAndOr struct {
	ConditionCount int32             `asn1:"explicit,tag:0" json:"condition_count"`
	Elements       AuthorizationData `asn1:"explicit,tag:1" json:"elements"`
}

// ADMandatoryForKDC implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6.4
type ADMandatoryForKDC AuthorizationData

// Unmarshal bytes into the ADKDCIssued.
func (a *ADKDCIssued) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

// Unmarshal bytes into the AuthorizationData.
func (a *AuthorizationData) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

// Unmarshal bytes into the AuthorizationDataEntry.
func (a *AuthorizationDataEntry) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}
