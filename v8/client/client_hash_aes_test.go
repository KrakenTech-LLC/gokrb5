package client

import (
	"bytes"
	"testing"

	"github.com/KrakenTech-LLC/gokrb5/v8/config"
	"github.com/KrakenTech-LLC/gokrb5/v8/crypto"
)

func testConfig() *config.Config {
	return &config.Config{
		LibDefaults: config.LibDefaults{
			DNSLookupKDC: false,
		},
		Realms: []config.Realm{
			{
				Realm: "RABBITHOLE.LOL",
				KDC:   []string{"dc1.rabbithole.lol"},
			},
		},
	}
}

func TestNewWithHashIsConfigured(t *testing.T) {
	cl := NewWithHash("EVANTEST$", "RABBITHOLE.LOL", bytes.Repeat([]byte{0x41}, 16), testConfig())

	ok, err := cl.IsConfigured()
	if !ok || err != nil {
		t.Fatalf("IsConfigured() = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestNewWithKeyIsConfigured(t *testing.T) {
	cl := NewWithKey("EVANTEST$", "RABBITHOLE.LOL", bytes.Repeat([]byte{0x42}, 32), testConfig())

	ok, err := cl.IsConfigured()
	if !ok || err != nil {
		t.Fatalf("IsConfigured() = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestKeyUsesNTHashForRC4(t *testing.T) {
	hash := bytes.Repeat([]byte{0x43}, 16)
	cl := NewWithHash("EVANTEST$", "RABBITHOLE.LOL", hash, testConfig())
	et, err := crypto.GetEtype(23)
	if err != nil {
		t.Fatalf("GetEtype(23) error = %v", err)
	}

	key, _, err := cl.Key(et, 0, nil)
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if key.KeyType != 23 {
		t.Fatalf("key.KeyType = %d, want 23", key.KeyType)
	}
	if !bytes.Equal(key.KeyValue, hash) {
		t.Fatalf("key.KeyValue = %x, want %x", key.KeyValue, hash)
	}
}

func TestKeyUsesAESKeyForAES256(t *testing.T) {
	aesKey := bytes.Repeat([]byte{0x44}, 32)
	cl := NewWithKey("EVANTEST$", "RABBITHOLE.LOL", aesKey, testConfig())
	et, err := crypto.GetEtype(18)
	if err != nil {
		t.Fatalf("GetEtype(18) error = %v", err)
	}

	key, _, err := cl.Key(et, 0, nil)
	if err != nil {
		t.Fatalf("Key() error = %v", err)
	}
	if key.KeyType != 18 {
		t.Fatalf("key.KeyType = %d, want 18", key.KeyType)
	}
	if !bytes.Equal(key.KeyValue, aesKey) {
		t.Fatalf("key.KeyValue = %x, want %x", key.KeyValue, aesKey)
	}
}
