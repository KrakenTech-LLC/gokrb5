package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/KrakenTech-LLC/gokrb5/v8/iana"
	"github.com/KrakenTech-LLC/gokrb5/v8/iana/errorcode"
	"github.com/KrakenTech-LLC/gokrb5/v8/iana/msgtype"
	"github.com/KrakenTech-LLC/gokrb5/v8/iana/nametype"
	"github.com/KrakenTech-LLC/gokrb5/v8/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalMarshalKRBError(t *testing.T) {
	t.Parallel()
	var a KRBError
	b, err := hex.DecodeString(testdata.MarshaledKRB5error)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO is not as expected")
	assert.Equal(t, msgtype.KRB_ERROR, a.MsgType, "Message type is not as expected")
	assert.Equal(t, tt, a.CTime, "CTime not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.STime, "STime not as expected")
	assert.Equal(t, 123456, a.Susec, "Service microseconds not as expected")
	assert.Equal(t, errorcode.KRB_ERR_GENERIC, a.ErrorCode, "Error code not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "Ticket SName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "Ticket SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "Ticket SName name string entries not as expected")
	assert.Equal(t, "krb5data", a.EText, "EText not as expected")
	assert.Equal(t, []byte("krb5data"), a.EData, "EData not as expected")

	b2, err := a.Marshal()
	if err != nil {
		t.Errorf("error marshalling KRBError: %v", err)
	}
	assert.Equal(t, b, b2, "marshalled bytes not as expected")
}

func TestUnmarshalMarshalKRBError_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a KRBError
	b, err := hex.DecodeString(testdata.MarshaledKRB5errorOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO is not as expected")
	assert.Equal(t, msgtype.KRB_ERROR, a.MsgType, "Message type is not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.STime, "STime not as expected")
	assert.Equal(t, 123456, a.Susec, "Service microseconds not as expected")
	assert.Equal(t, errorcode.KRB_ERR_GENERIC, a.ErrorCode, "Error code not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "Ticket SName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "Ticket SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "Ticket SName name string entries not as expected")

	b2, err := a.Marshal()
	if err != nil {
		t.Errorf("error marshalling KRBError: %v", err)
	}
	assert.Equal(t, b, b2, "marshalled bytes not as expected")
}
