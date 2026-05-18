package main

import (
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
		serial              int
		entry               *EntryConfig
		expectedTBSHex      string
		expectedLogEntryHex string
	}{
		// A minimal TBSCertificate
		{
			version: VersionPlants02,
			issuer:  issuer,
			serial:  1234,
			entry: &EntryConfig{
				PublicKey: publicKey,
				NotBefore: time.Unix(1577836800, 0), // 2020-01-01 00:00:00
				NotAfter:  time.Unix(1609459199, 0), // 2020-12-31 23:59:59
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
				PublicKey:   publicKey,
				NotBefore:   time.Unix(1577836800, 0), // 2020-01-01 00:00:00
				NotAfter:    time.Unix(1609459199, 0), // 2020-12-31 23:59:59
				DNSNames:    []string{"example.com", "a.example", "*.b.example"},
				KeyUsage:    KeyUsageConfig(x509.KeyUsageDigitalSignature),
				ExtKeyUsage: []ExtKeyUsageConfig{ExtKeyUsageConfig(oidServerAuth)},
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
				PublicKey:  publicKey,
				NotBefore:  time.Unix(1577836800, 0), // 2020-01-01 00:00:00
				NotAfter:   time.Unix(1609459199, 0), // 2020-12-31 23:59:59
				KeyUsage:   KeyUsageConfig(x509.KeyUsageCertSign),
				IsCA:       ptrOf(true),
				MaxPathLen: ptrOf(int64(5)),
			},
			expectedTBSHex:      "3081e7a003020102020204d2300c060a2b0601040182da4b2f00301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a3010310e300c06035504031305412043413f3059301306072a8648ce3d020106082a8648ce3d03010703420004e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1a3263024300e0603551d0f0101ff04040302020430120603551d130101ff040830060101ff020105",
			expectedLogEntryHex: "0001a003020102301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a3010310e300c06035504031305412043413f301306072a8648ce3d020106082a8648ce3d0301070420b3aea0f0a50538874f2b4c912f2676bd25ccc3dae700e20dcad42d3d5c074ca5a3263024300e0603551d0f0101ff04040302020430120603551d130101ff040830060101ff020105",
		},
		// draft-plants-04 added an extensions field to
		// MerkleTreeCertEntry.
		{
			version: VersionPlants04,
			issuer:  issuer,
			serial:  1234,
			entry: &EntryConfig{
				PublicKey: publicKey,
				NotBefore: time.Unix(1577836800, 0), // 2020-01-01 00:00:00
				NotAfter:  time.Unix(1609459199, 0), // 2020-12-31 23:59:59
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
				NotBefore: time.Unix(1577836800, 0), // 2020-01-01 00:00:00
				NotAfter:  time.Unix(1609459199, 0), // 2020-12-31 23:59:59
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
				NotBefore: time.Unix(1577836800, 0), // 2020-01-01 00:00:00
				NotAfter:  time.Unix(1609459199, 0), // 2020-12-31 23:59:59
			},
			expectedTBSHex:      "3081afa003020102020204d2300c060a2b0601040182da4b2f00301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a30003059301306072a8648ce3d020106082a8648ce3d03010703420004e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1",
			expectedLogEntryHex: "0001a003020102301931173015060a2b0601040182da4b2f010c0733323437332e31301e170d3230303130313030303030305a170d3230313233313233353935395a30000420b3aea0f0a50538874f2b4c912f2676bd25ccc3dae700e20dcad42d3d5c074ca5",
		},
	}
	for i, tt := range tests {
		b := cryptobyte.NewBuilder(nil)
		AddTBSCertificate(b, tt.issuer, tt.serial, tt.entry)
		tbs, err := b.Bytes()
		if err != nil {
			t.Errorf("%d. AddTBSCertificate() failed: %s", i, err)
		} else if got := hex.EncodeToString(tbs); got != tt.expectedTBSHex {
			t.Errorf("%d. AddTBSCertificate() gave %s, wanted %s", i, got, tt.expectedTBSHex)
		}

		log, err := MarshalTBSCertificateLogEntry(tt.version, tt.issuer, tt.entry)
		if err != nil {
			t.Errorf("%d. MarshalTBSCertificateLogEntry() failed: %s", i, err)
		} else if got := hex.EncodeToString(log); got != tt.expectedLogEntryHex {
			t.Errorf("%d. MarshalTBSCertificateLogEntry() gave %s, wanted %s", i, got, tt.expectedLogEntryHex)
		}
	}
}
