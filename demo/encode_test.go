package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

func ptrOf[T any](t T) *T { return &t }

func TestMarshalTBSCertificate(t *testing.T) {
	issuer, ok := TrustAnchorIDFromString("32473.1")
	if !ok {
		t.Fatalf("could not make trust anchor ID")
	}
	publicKey := []byte{
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
		0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
		0x42, 0x00, 0x04, 0xe6, 0x2b, 0x69, 0xe2, 0xbf, 0x65, 0x9f, 0x97, 0xbe,
		0x2f, 0x1e, 0x0d, 0x94, 0x8a, 0x4c, 0xd5, 0x97, 0x6b, 0xb7, 0xa9, 0x1e,
		0x0d, 0x46, 0xfb, 0xdd, 0xa9, 0xa9, 0x1e, 0x9d, 0xdc, 0xba, 0x5a, 0x01,
		0xe7, 0xd6, 0x97, 0xa8, 0x0a, 0x18, 0xf9, 0xc3, 0xc4, 0xa3, 0x1e, 0x56,
		0xe2, 0x7c, 0x83, 0x48, 0xdb, 0x16, 0x1a, 0x1c, 0xf5, 0x1d, 0x7e, 0xf1,
		0x94, 0x2d, 0x4b, 0xcf, 0x72, 0x22, 0xc1,
	}

	var tests = []struct {
		version             DraftVersion
		issuer              TrustAnchorID
		serial              uint64
		entry               *EntryConfig
		expectedTBSHex      string
		expectedLogEntryHex string
	}{
		// A null entry.
		{
			version:             VersionPlants02,
			entry:               &EntryConfig{Null: true},
			expectedLogEntryHex: "0000",
		},
		// A minimal TBSCertificate
		{
			version: VersionPlants02,
			issuer:  issuer,
			serial:  1234,
			entry: &EntryConfig{
				PublicKey: publicKey,
				CertConfigBase: CertConfigBase{
					NotBefore: time.Unix(1577836800, 0), // 2020-01-01 00:00:00
					NotAfter:  time.Unix(1609459199, 0), // 2020-12-31 23:59:59
				},
			},
			expectedTBSHex:      "3081afa003020102020204d2300c060a2b0601040182da4b2f00301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a30003059301306072a8648ce3d020106082a8648ce3d03010703420004e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1",
			expectedLogEntryHex: "0001a003020102301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a3000301306072a8648ce3d020106082a8648ce3d0301070420b3aea0f0a50538874f2b4c912f2676bd25ccc3dae700e20dcad42d3d5c074ca5",
		},
		// Fill in a bit of everything.
		{
			version: VersionPlants02,
			issuer:  issuer,
			serial:  1234,
			entry: &EntryConfig{
				Subject: SubjectConfig{
					CommonName: "example.com",
				},
				PublicKey: publicKey,
				CertConfigBase: CertConfigBase{
					NotBefore:   time.Unix(1577836800, 0), // 2020-01-01 00:00:00
					NotAfter:    time.Unix(1609459199, 0), // 2020-12-31 23:59:59
					DNSNames:    []string{"example.com", "a.example", "*.b.example"},
					KeyUsage:    KeyUsageConfig(x509.KeyUsageDigitalSignature),
					ExtKeyUsage: []ExtKeyUsageConfig{ExtKeyUsageConfig(oidServerAuth)},
				},
			},
			expectedTBSHex:      "30820124a003020102020204d2300c060a2b0601040182da4b2f00301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a3016311430120603550403130b6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1a35d305b300e0603551d0f0101ff04040302078030160603551d250101ff040c300a06082b0601050507030130310603551d110101ff04273025820b6578616d706c652e636f6d8209612e6578616d706c65820b2a2e622e6578616d706c65",
			expectedLogEntryHex: "0001a003020102301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a3016311430120603550403130b6578616d706c652e636f6d301306072a8648ce3d020106082a8648ce3d0301070420b3aea0f0a50538874f2b4c912f2676bd25ccc3dae700e20dcad42d3d5c074ca5a35d305b300e0603551d0f0101ff04040302078030160603551d250101ff040c300a06082b0601050507030130310603551d110101ff04273025820b6578616d706c652e636f6d8209612e6578616d706c65820b2a2e622e6578616d706c65",
		},
		// Generate a CA too, even though it's a little questionable. See
		// https://github.com/ietf-plants-wg/merkle-tree-certs/issues/146
		{
			version: VersionPlants02,
			issuer:  issuer,
			serial:  1234,
			entry: &EntryConfig{
				Subject: SubjectConfig{
					CommonName: "A CA?",
				},
				PublicKey: publicKey,
				CertConfigBase: CertConfigBase{
					NotBefore:  time.Unix(1577836800, 0), // 2020-01-01 00:00:00
					NotAfter:   time.Unix(1609459199, 0), // 2020-12-31 23:59:59
					KeyUsage:   KeyUsageConfig(x509.KeyUsageCertSign),
					IsCA:       ptrOf(true),
					MaxPathLen: ptrOf(int64(5)),
				},
			},
			expectedTBSHex:      "3081e7a003020102020204d2300c060a2b0601040182da4b2f00301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a3010310e300c06035504031305412043413f3059301306072a8648ce3d020106082a8648ce3d03010703420004e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1a3263024300e0603551d0f0101ff04040302020430120603551d130101ff040830060101ff020105",
			expectedLogEntryHex: "0001a003020102301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a3010310e300c06035504031305412043413f301306072a8648ce3d020106082a8648ce3d0301070420b3aea0f0a50538874f2b4c912f2676bd25ccc3dae700e20dcad42d3d5c074ca5a3263024300e0603551d0f0101ff04040302020430120603551d130101ff040830060101ff020105",
		},
		// draft-plants-06 uses RELATIVE-OID for the X.509 name.
		{
			version: VersionPlants06,
			issuer:  issuer,
			serial:  1234,
			entry: &EntryConfig{
				PublicKey: publicKey,
				CertConfigBase: CertConfigBase{
					NotBefore: time.Unix(1577836800, 0), // 2020-01-01 00:00:00
					NotAfter:  time.Unix(1609459199, 0), // 2020-12-31 23:59:59
				},
			},
			expectedTBSHex:      "3081aca003020102020204d2300c060a2b0601040182da4b2f00301631143012060a2b0601040182da4b2f030d0481fd5901301e170d3230303130313030303030305a170d3230313233313233353935395a30003059301306072a8648ce3d020106082a8648ce3d03010703420004e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1",
			expectedLogEntryHex: "00000001a003020102301631143012060a2b0601040182da4b2f030d0481fd5901301e170d3230303130313030303030305a170d3230313233313233353935395a3000301306072a8648ce3d020106082a8648ce3d0301070420b3aea0f0a50538874f2b4c912f2676bd25ccc3dae700e20dcad42d3d5c074ca5",
		},
		// draft-plants-07 has PKIX OIDs.
		{
			version: VersionPlants07,
			issuer:  issuer,
			serial:  1234,
			entry: &EntryConfig{
				PublicKey: publicKey,
				CertConfigBase: CertConfigBase{
					NotBefore: time.Unix(1577836800, 0), // 2020-01-01 00:00:00
					NotAfter:  time.Unix(1609459199, 0), // 2020-12-31 23:59:59
				},
			},
			expectedTBSHex:      "3081a8a003020102020204d2300a06082b0601050507064330143112301006082b060105050719030d0481fd5901301e170d3230303130313030303030305a170d3230313233313233353935395a30003059301306072a8648ce3d020106082a8648ce3d03010703420004e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1",
			expectedLogEntryHex: "00000001a00302010230143112301006082b060105050719030d0481fd5901301e170d3230303130313030303030305a170d3230313233313233353935395a3000301306072a8648ce3d020106082a8648ce3d0301070420b3aea0f0a50538874f2b4c912f2676bd25ccc3dae700e20dcad42d3d5c074ca5",
		},
		// draft-plants-04 added an extensions field to
		// MerkleTreeCertEntry.
		{
			version: VersionPlants04,
			issuer:  issuer,
			serial:  1234,
			entry: &EntryConfig{
				PublicKey: publicKey,
				CertConfigBase: CertConfigBase{
					NotBefore: time.Unix(1577836800, 0), // 2020-01-01 00:00:00
					NotAfter:  time.Unix(1609459199, 0), // 2020-12-31 23:59:59
				},
			},
			expectedTBSHex:      "3081afa003020102020204d2300c060a2b0601040182da4b2f00301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a30003059301306072a8648ce3d020106082a8648ce3d03010703420004e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1",
			expectedLogEntryHex: "00000001a003020102301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a3000301306072a8648ce3d020106082a8648ce3d0301070420b3aea0f0a50538874f2b4c912f2676bd25ccc3dae700e20dcad42d3d5c074ca5",
		},
		// draft-davidben-09 included a TBSCertificate wrapper TLV.
		{
			version: VersionDavidben09,
			issuer:  issuer,
			serial:  1234,
			entry: &EntryConfig{
				PublicKey: publicKey,
				CertConfigBase: CertConfigBase{
					NotBefore: time.Unix(1577836800, 0), // 2020-01-01 00:00:00
					NotAfter:  time.Unix(1609459199, 0), // 2020-12-31 23:59:59
				},
			},
			expectedTBSHex:      "3081afa003020102020204d2300c060a2b0601040182da4b2f00301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a30003059301306072a8648ce3d020106082a8648ce3d03010703420004e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1",
			expectedLogEntryHex: "00013064a003020102301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a30000420b3aea0f0a50538874f2b4c912f2676bd25ccc3dae700e20dcad42d3d5c074ca5",
		},
		// draft-plants-01 omitted the public key algorithm.
		{
			version: VersionPlants01,
			issuer:  issuer,
			serial:  1234,
			entry: &EntryConfig{
				PublicKey: publicKey,
				CertConfigBase: CertConfigBase{
					NotBefore: time.Unix(1577836800, 0), // 2020-01-01 00:00:00
					NotAfter:  time.Unix(1609459199, 0), // 2020-12-31 23:59:59
				},
			},
			expectedTBSHex:      "3081afa003020102020204d2300c060a2b0601040182da4b2f00301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a30003059301306072a8648ce3d020106082a8648ce3d03010703420004e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1",
			expectedLogEntryHex: "0001a003020102301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a30000420b3aea0f0a50538874f2b4c912f2676bd25ccc3dae700e20dcad42d3d5c074ca5",
		},
	}
	for i, tt := range tests {
		if !tt.entry.Null {
			b := cryptobyte.NewBuilder(nil)
			AddTBSCertificate(b, tt.version, tt.issuer, tt.serial, tt.entry, &CertificateConfig{})
			tbs, err := b.Bytes()
			if err != nil {
				t.Errorf("%d. AddTBSCertificate() failed: %s", i, err)
			} else if got := hex.EncodeToString(tbs); got != tt.expectedTBSHex {
				t.Errorf("%d. AddTBSCertificate() gave %s, wanted %s", i, got, tt.expectedTBSHex)
			}
		}

		log, err := MarshalTBSCertificateLogEntry(tt.version, tt.issuer, tt.entry)
		if err != nil {
			t.Errorf("%d. MarshalTBSCertificateLogEntry() failed: %s", i, err)
		} else if got := hex.EncodeToString(log); got != tt.expectedLogEntryHex {
			t.Errorf("%d. MarshalTBSCertificateLogEntry() gave %s, wanted %s", i, got, tt.expectedLogEntryHex)
		}
	}
}

func TestMTCProofSignaturesLengthPrefix(t *testing.T) {
	tests := []struct {
		name      string
		version   DraftVersion
		length    int
		prefixLen int
		wantError bool
	}{
		{"plants-05", VersionPlants05, 123, 2, false},
		{"plants-05-too-long", VersionPlants05, 1 << 16, 2, true},
		{"plants-06", VersionPlants06, 123, 3, false},
		{"plants-06-above-old-limit", VersionPlants06, 1 << 16, 3, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0x42}, tt.length)
			b := cryptobyte.NewBuilder(nil)
			addMTCProofSignatures(b, tt.version, func(child *cryptobyte.Builder) {
				child.AddBytes(payload)
			})
			encoded, err := b.Bytes()
			if tt.wantError {
				if err == nil {
					t.Fatal("encoding unexpectedly succeeded")
				}
				return
			}
			if err != nil {
				t.Fatalf("encoding failed: %v", err)
			}
			if len(encoded) != tt.prefixLen+len(payload) {
				t.Fatalf("encoded length = %d, want %d", len(encoded), tt.prefixLen+len(payload))
			}

			in := cryptobyte.String(encoded)
			var decoded cryptobyte.String
			if !readMTCProofSignatures(&in, tt.version, &decoded) || !in.Empty() {
				t.Fatal("decoding failed")
			}
			if !bytes.Equal(decoded, payload) {
				t.Fatal("decoded payload does not match input")
			}

			otherVersion := VersionPlants05
			if tt.version == VersionPlants05 {
				otherVersion = VersionPlants06
			}
			in = encoded
			if readMTCProofSignatures(&in, otherVersion, &decoded) && in.Empty() {
				t.Fatal("decoding with another draft version unexpectedly succeeded")
			}
		})
	}
}
