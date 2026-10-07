package main

import (
	"crypto"
	"crypto/mldsa"
	"encoding/binary"
	"testing"
)

// TestCheckpointCosignature checks the checkpoint cosignature against
// https://c2sp.org/tlog-cosignature@v1.1.0: the timestamp as an eight-byte,
// big-endian integer, then an ML-DSA-44 signature over a CosignedSubtree
// carrying that timestamp.
func TestCheckpointCosignature(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	cosignerID, ok := TrustAnchorIDFromString("32473.1")
	if !ok {
		t.Fatal("bad cosigner ID")
	}
	logID, ok := TrustAnchorIDFromString("32473.1.0.1")
	if !ok {
		t.Fatal("bad log ID")
	}
	cosigner := &Cosigner{
		Version:            VersionPlants07,
		ID:                 cosignerID,
		SignatureAlgorithm: SignatureAlgorithmMLDSA44,
		Signer:             priv,
		SignerOpts:         crypto.Hash(0),
	}
	var hash HashValue
	for i := range hash {
		hash[i] = byte(i)
	}
	const size, timestamp = 10, 1790000000

	cosig, err := cosigner.SignCheckpoint(logID, size, timestamp, &hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(cosig) <= 8 || binary.BigEndian.Uint64(cosig[:8]) != timestamp {
		t.Fatalf("cosignature does not start with the timestamp %d", timestamp)
	}
	msg, err := cosignedMessage(VersionPlants07, cosignerID, logID, timestamp, 0, size, &hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := mldsa.Verify(priv.PublicKey(), msg, cosig[8:], nil); err != nil {
		t.Errorf("signature does not verify over the timestamped message: %v", err)
	}
	// The timestamp is signed: the same signature does not verify over the
	// subtree cosignature's message, whose timestamp is zero.
	msg0, err := cosignedMessage(VersionPlants07, cosignerID, logID, 0, 0, size, &hash)
	if err != nil {
		t.Fatal(err)
	}
	if mldsa.Verify(priv.PublicKey(), msg0, cosig[8:], nil) == nil {
		t.Error("signature unexpectedly verifies with a zero timestamp")
	}

	// Subtree cosignatures, as in certificates, are unchanged: no timestamp.
	sig, err := cosigner.Sign(logID, 0, size, &hash)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := NewCosignerPublic(VersionPlants07, cosignerID, SignatureAlgorithmMLDSA44, priv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(logID, 0, size, &hash, sig); err != nil {
		t.Errorf("subtree cosignature does not verify: %v", err)
	}

	// Only a checkpoint, starting at zero, has a timestamp.
	if _, err := cosignedMessage(VersionPlants07, cosignerID, logID, timestamp, 2, 4, &hash); err == nil {
		t.Error("timestamped message for a subtree not starting at zero")
	}
}
