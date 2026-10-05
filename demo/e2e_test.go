package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// End-to-end certificate encoding test vector for draft-plants-05.
// Regenerates demo/e2e_certificate.{txt,json} when run with -update.

func e2ePublicKey() []byte {
	return []byte{
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
		0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
		0x42, 0x00, 0x04, 0xe6, 0x2b, 0x69, 0xe2, 0xbf, 0x65, 0x9f, 0x97, 0xbe,
		0x2f, 0x1e, 0x0d, 0x94, 0x8a, 0x4c, 0xd5, 0x97, 0x6b, 0xb7, 0xa9, 0x1e,
		0x0d, 0x46, 0xfb, 0xdd, 0xa9, 0xa9, 0x1e, 0x9d, 0xdc, 0xba, 0x5a, 0x01,
		0xe7, 0xd6, 0x97, 0xa8, 0x0a, 0x18, 0xf9, 0xc3, 0xc4, 0xa3, 0x1e, 0x56,
		0xe2, 0x7c, 0x83, 0x48, 0xdb, 0x16, 0x1a, 0x1c, 0xf5, 0x1d, 0x7e, 0xf1,
		0x94, 0x2d, 0x4b, 0xcf, 0x72, 0x22, 0xc1,
	}
}

func e2eCAPrivateKey() []byte {
	// Ed25519 PKCS#8 for seed 01..20, used so cosignatures are deterministic.
	pkcs8, err := base64.StdEncoding.DecodeString(
		"MC4CAQAwBQYDK2VwBCIEIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g")
	if err != nil {
		panic(err)
	}
	return pkcs8
}

type e2eCertificateVector struct {
	Version                    string
	CAID                       string
	LogNumber                  uint16
	Index                      uint64
	Serial                     uint64
	SubtreeStart, SubtreeEnd   uint64
	SubjectPublicKeyInfo       []byte
	SubjectPublicKeyInfoHash   []byte
	MTCLogEntry                []byte
	EntryHash                  []byte
	NullEntry                  []byte
	NullEntryHash              []byte
	SubtreeHash                []byte
	InclusionProof             []byte
	CosignedMessage            []byte
	CosignerID                 string
	Cosignature                []byte
	MTCProof                   []byte
	Certificate                []byte
	CACertificate              []byte
}

func TestE2ECertificateVector(t *testing.T) {
	caID, ok := TrustAnchorIDFromString("32473.1")
	if !ok {
		t.Fatal("could not parse CA ID")
	}

	entry := &EntryConfig{
		Subject: SubjectConfig{
			CommonName: "example.com",
		},
		PublicKey: e2ePublicKey(),
		CertConfigBase: CertConfigBase{
			NotBefore:   time.Unix(1577836800, 0), // 2020-01-01 00:00:00 UTC
			NotAfter:    time.Unix(1609459199, 0), // 2020-12-31 23:59:59 UTC
			DNSNames:    []string{"example.com", "a.example", "*.b.example"},
			KeyUsage:    KeyUsageConfig(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: []ExtKeyUsageConfig{ExtKeyUsageConfig(oidServerAuth)},
		},
		Certificates: []CertificateConfig{{
			SubtreeStart: 0,
			SubtreeEnd:   2,
			Cosigners:    []TrustAnchorID{caID},
		}},
	}

	config := &CAConfig{
		Version:   VersionPlants05,
		ID:        caID,
		LogNumber: 1,
		Cosigners: []CosignerConfig{{
			CosignerID:         caID,
			SignatureAlgorithm: SignatureAlgorithmEd25519,
			PrivateKey:         e2eCAPrivateKey(),
		}},
		CACert: CACertConfig{
			CertConfigBase: CertConfigBase{
				NotBefore: time.Unix(1577836800, 0),
				NotAfter:  time.Unix(1893455999, 0), // 2029-12-31 23:59:59 UTC
				IsCA:      ptrOf(true),
				KeyUsage:  KeyUsageConfig(x509.KeyUsageCertSign),
			},
			MinSerial: SerialConfig{Log: 1, Index: 0},
			MaxSerial: SerialConfig{Log: 1, Index: 1<<48 - 1},
		},
	}

	cosigner, err := NewCosignerFromConfig(config.Version, &config.Cosigners[0])
	if err != nil {
		t.Fatalf("NewCosignerFromConfig: %v", err)
	}

	caCertDER, err := CreateCACertificate(config, cosigner)
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}

	const index, start, end = uint64(0), uint64(0), uint64(2)

	logEntry, err := MarshalTBSCertificateLogEntry(config.Version, config.ID, entry)
	if err != nil {
		t.Fatalf("MarshalTBSCertificateLogEntry: %v", err)
	}
	nullEntry := MarshalNullEntry(config.Version)
	tree := NewStaticMerkleTree([][]byte{logEntry, nullEntry})

	entryHash := HashLeaf(logEntry)
	nullHash := HashLeaf(nullEntry)
	subtreeHash, err := SubtreeHash(tree, start, end)
	if err != nil {
		t.Fatalf("SubtreeHash: %v", err)
	}
	proof, err := SubtreeInclusionProof(tree, index, start, end)
	if err != nil {
		t.Fatalf("SubtreeInclusionProof: %v", err)
	}
	evaluated, err := EvaluateSubtreeInclusionProof(index, start, end, &entryHash, proof)
	if err != nil {
		t.Fatalf("EvaluateSubtreeInclusionProof: %v", err)
	}
	if !bytes.Equal(evaluated[:], subtreeHash[:]) {
		t.Fatalf("inclusion proof evaluated to %x, want %x", evaluated, subtreeHash)
	}

	logID := LogIDForConfig(config)
	cosignedMsg, err := cosignedMessage(config.Version, cosigner.ID, logID, start, end, &subtreeHash)
	if err != nil {
		t.Fatalf("cosignedMessage: %v", err)
	}
	cosig, err := cosigner.Sign(logID, start, end, &subtreeHash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	certDER, err := CreateCertificate(config, tree, []*Cosigner{cosigner}, entry, &entry.Certificates[0], index, start, end)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	mtcProof, err := certSignatureBytes(cert)
	if err != nil {
		t.Fatalf("certSignatureBytes: %v", err)
	}

	spkiHash := sha256.Sum256(entry.PublicKey)
	serial := index | (uint64(config.LogNumber) << 48)

	vector := e2eCertificateVector{
		Version:                  config.Version.String(),
		CAID:                     config.ID.String(),
		LogNumber:                config.LogNumber,
		Index:                    index,
		Serial:                   serial,
		SubtreeStart:             start,
		SubtreeEnd:               end,
		SubjectPublicKeyInfo:     entry.PublicKey,
		SubjectPublicKeyInfoHash: spkiHash[:],
		MTCLogEntry:              logEntry,
		EntryHash:                entryHash[:],
		NullEntry:                nullEntry,
		NullEntryHash:            nullHash[:],
		SubtreeHash:              subtreeHash[:],
		InclusionProof:           proof,
		CosignedMessage:          cosignedMsg,
		CosignerID:               cosigner.ID.String(),
		Cosignature:              cosig,
		MTCProof:                 mtcProof,
		Certificate:              certDER,
		CACertificate:            caCertDER,
	}

	jsonBytes, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent: %v", err)
	}
	jsonBytes = append(jsonBytes, '\n')

	var text bytes.Buffer
	fmt.Fprintf(&text, "End-to-end Merkle Tree Certificate test vector (%s)\n", config.Version)
	fmt.Fprintf(&text, "Also available in machine-readable form in e2e_certificate.json\n\n")
	fmt.Fprintf(&text, "CA ID: %s\n", vector.CAID)
	fmt.Fprintf(&text, "Log number: %d\n", vector.LogNumber)
	fmt.Fprintf(&text, "Entry index: %d\n", vector.Index)
	fmt.Fprintf(&text, "Certificate serial: 0x%x\n", vector.Serial)
	fmt.Fprintf(&text, "Subtree: [%d, %d)\n\n", vector.SubtreeStart, vector.SubtreeEnd)

	fmt.Fprintf(&text, "SubjectPublicKeyInfo (DER):\n  %x\n\n", vector.SubjectPublicKeyInfo)
	fmt.Fprintf(&text, "SHA-256(SubjectPublicKeyInfo):\n  %x\n\n", vector.SubjectPublicKeyInfoHash)

	fmt.Fprintf(&text, "MTCLogEntry for the tbs_cert_entry (index %d):\n  %x\n\n", vector.Index, vector.MTCLogEntry)
	fmt.Fprintf(&text, "entry_hash = SHA-256(0x00 || MTCLogEntry):\n  %x\n\n", vector.EntryHash)

	fmt.Fprintf(&text, "MTCLogEntry for the null_entry (index 1):\n  %x\n\n", vector.NullEntry)
	fmt.Fprintf(&text, "null entry_hash:\n  %x\n\n", vector.NullEntryHash)

	fmt.Fprintf(&text, "Subtree hash MTH(D[%d:%d]):\n  %x\n\n", vector.SubtreeStart, vector.SubtreeEnd, vector.SubtreeHash)
	fmt.Fprintf(&text, "Inclusion proof for index %d in [%d, %d):\n", vector.Index, vector.SubtreeStart, vector.SubtreeEnd)
	for off := 0; off < len(vector.InclusionProof); off += HashSize {
		fmt.Fprintf(&text, "  %x\n", vector.InclusionProof[off:off+HashSize])
	}
	fmt.Fprintf(&text, "\n")

	fmt.Fprintf(&text, "CosignedMessage (cosigner %s):\n  %x\n\n", vector.CosignerID, vector.CosignedMessage)
	fmt.Fprintf(&text, "Ed25519 cosignature:\n  %x\n\n", vector.Cosignature)

	fmt.Fprintf(&text, "MTCProof (contents of Certificate.signatureValue):\n  %x\n\n", vector.MTCProof)
	fmt.Fprintf(&text, "Certificate (DER):\n  %x\n\n", vector.Certificate)
	fmt.Fprintf(&text, "CA Certificate (DER):\n  %x\n", vector.CACertificate)

	checkOrUpdateTestVectors(t, "e2e_certificate.txt", text.Bytes())
	checkOrUpdateTestVectors(t, "e2e_certificate.json", jsonBytes)

	// Round-trip: the generated certificate must verify under a CA-only policy.
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("ParseCertificate(CA): %v", err)
	}
	policy := Policy{Version: VersionPlants05}
	if err := policy.AddCA(caCert); err != nil {
		t.Fatalf("AddCA: %v", err)
	}
	result, err := VerifyMTCProof(cert, &policy, VersionPlants05)
	if err != nil {
		t.Fatalf("VerifyMTCProof: %v", err)
	}
	if result.TrustedSubtree {
		t.Fatalf("expected standalone cosignature path, got trusted subtree")
	}
}
