package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type parsedSignature struct {
	cosignerID TrustAnchorID
	signature  []byte
}

func hashU16(dst hash.Hash, v uint16) {
	dst.Write([]byte{byte(v >> 8), byte(v)})
}

func hashU16LengthPrefixed(dst hash.Hash, in []byte) {
	if len(in) > 0xffff {
		panic("input too long")
	}
	hashU16(dst, uint16(len(in)))
	dst.Write(in)
}

func hashASN1Element(dst hash.Hash, src *cryptobyte.String, tag cbasn1.Tag) bool {
	var elem cryptobyte.String
	if !src.ReadASN1Element(&elem, tag) {
		return false
	}
	dst.Write(elem)
	return true
}

type VerifyResult struct {
	TrustedSubtree          bool
	VerifyErrors            []error
	PolicyResult            PolicyResult
	UnsatisfiedRequirements []PolicyIndex
}

func VerifyMTCProof(cert *x509.Certificate, policy *Policy, version DraftVersion) (*VerifyResult, error) {
	caID, err := caIDFromX509Name(cert.RawIssuer)
	if err != nil {
		return nil, fmt.Errorf("issuer not an MTC CA: %w", err)
	}
	ca, ok := policy.CAs[caID.String()]
	if !ok || ca.Certificate == nil {
		return nil, fmt.Errorf("issuer %s not a known MTC CA", caID)
	}

	if !bytes.Equal(cert.RawSignatureAlgorithm, mtcProofSigAlg) {
		return nil, errors.New("signature algorithm was not an mtcProof")
	}

	proofStr := cryptobyte.String(cert.Signature)
	var start, end uint64
	var signatures []parsedSignature
	var proofExtensions, inclusionProof, sigs cryptobyte.String
	if !proofStr.ReadUint16LengthPrefixed(&proofExtensions) ||
		!proofStr.ReadUint48(&start) ||
		!proofStr.ReadUint48(&end) ||
		!proofStr.ReadUint16LengthPrefixed(&inclusionProof) ||
		!proofStr.ReadUint16LengthPrefixed(&sigs) ||
		!proofStr.Empty() {
		return nil, fmt.Errorf("malformed MTCProof")
	}

	var prevID TrustAnchorID
	for !sigs.Empty() {
		var cosignerID, sigVal cryptobyte.String
		if !sigs.ReadUint8LengthPrefixed(&cosignerID) || len(cosignerID) == 0 ||
			!sigs.ReadUint16LengthPrefixed(&sigVal) {
			return nil, fmt.Errorf("malformed signature in MTCProof")
		}
		if prevID != nil && compareCosignerIDs(prevID, TrustAnchorID(cosignerID)) >= 0 {
			return nil, fmt.Errorf("cosigners not in canonical order or duplicate: %s and %s", prevID, TrustAnchorID(cosignerID))
		}
		prevID = TrustAnchorID(cosignerID)
		signatures = append(signatures, parsedSignature{
			cosignerID: TrustAnchorID(cosignerID),
			signature:  sigVal,
		})
	}

	entryHash := sha256.New()
	entryHash.Write([]byte{0x00}) // MTC leaf domain separator
	hashU16LengthPrefixed(entryHash, proofExtensions)
	hashU16(entryHash, entryTypeTBSCert)

	var tbs cryptobyte.String
	tbsElem := cryptobyte.String(cert.RawTBSCertificate)
	if !tbsElem.ReadASN1(&tbs, cbasn1.SEQUENCE) || !tbsElem.Empty() {
		return nil, fmt.Errorf("malformed TBSCertificate")
	}
	if tbs.PeekASN1Tag(cbasn1.Tag(0).Constructed().ContextSpecific()) &&
		!hashASN1Element(entryHash, &tbs, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, fmt.Errorf("malformed TBSCertificate")
	}
	var serial uint64
	var tbsSigAlg, spki cryptobyte.String
	if !tbs.ReadASN1Integer(&serial) ||
		!tbs.ReadASN1Element(&tbsSigAlg, cbasn1.SEQUENCE) ||
		!bytes.Equal(tbsSigAlg, mtcProofSigAlg) ||
		!hashASN1Element(entryHash, &tbs, cbasn1.SEQUENCE) || // issuer
		!hashASN1Element(entryHash, &tbs, cbasn1.SEQUENCE) || // validity
		!hashASN1Element(entryHash, &tbs, cbasn1.SEQUENCE) || // subject
		!tbs.ReadASN1(&spki, cbasn1.SEQUENCE) ||
		!hashASN1Element(entryHash, &spki, cbasn1.SEQUENCE) { // SPKI algorithm
		return nil, fmt.Errorf("malformed TBSCertificate")
	}

	// Write the SPKI hash and the rest of the TBSCertificate.
	entryHash.Write([]byte{0x04, 32}) // OCTET STRING, 32 bytes
	spkiHash := sha256.New()
	spkiHash.Write(cert.RawSubjectPublicKeyInfo)
	entryHash.Write(spkiHash.Sum(nil))
	entryHash.Write(tbs)

	for _, r := range ca.RevokedRanges {
		if serial >= r.MinSerial && serial <= r.MaxSerial {
			return nil, fmt.Errorf("certificate serial %d is revoked (range [%d, %d])", serial, r.MinSerial, r.MaxSerial)
		}
	}

	index := serial & (1<<48 - 1)
	log := uint16(serial >> 48)
	if log == 0 {
		return nil, fmt.Errorf("invalid log number 0 in serial")
	}
	logID := LogID(version, caID, log)

	subtreeHash, err := EvaluateSubtreeInclusionProof(index, start, end, (*HashValue)(entryHash.Sum(nil)), inclusionProof)
	if err != nil {
		return nil, fmt.Errorf("inclusion proof evaluation failed: %w", err)
	}

	if expected, ok := ca.FindTrustedSubtree(log, start, end); ok {
		if !bytes.Equal(expected[:], subtreeHash[:]) {
			return nil, fmt.Errorf("trusted subtree hash mismatch: expected %x, got %x", expected, subtreeHash)
		}
		return &VerifyResult{TrustedSubtree: true}, nil
	}

	cosignersSatisfied := make([]bool, len(policy.Cosigners))
	ret := &VerifyResult{}
	for _, sig := range signatures {
		idx, ok := policy.Names[sig.cosignerID.String()]
		if !ok || idx.IsGroup {
			// Unrecognized cosigners MUST be ignored.
			continue
		}
		cosigner := policy.Cosigners[idx.Index]
		if err := cosigner.Verify(logID, start, end, &subtreeHash, sig.signature); err != nil {
			ret.VerifyErrors = append(ret.VerifyErrors, fmt.Errorf("invalid signature from cosigner %s: %w", sig.cosignerID, err))
		} else {
			cosignersSatisfied[idx.Index] = true
		}
	}

	ret.PolicyResult = policy.EvaluateGroups(cosignersSatisfied)
	caIdx := PolicyIndex{IsGroup: false, Index: ca.CosignerIndex}
	if !ret.PolicyResult.Satisfied(caIdx) {
		ret.UnsatisfiedRequirements = append(ret.UnsatisfiedRequirements, caIdx)
	}

	for _, req := range ca.Requirements {
		if !ret.PolicyResult.Satisfied(req) {
			ret.UnsatisfiedRequirements = append(ret.UnsatisfiedRequirements, req)
		}
	}
	for _, req := range policy.RequirementsForAllCAs {
		if !ret.PolicyResult.Satisfied(req) {
			ret.UnsatisfiedRequirements = append(ret.UnsatisfiedRequirements, req)
		}
	}

	if len(ret.UnsatisfiedRequirements) != 0 {
		return ret, errors.New("cosigner policy not satisfied")
	}
	return ret, nil
}
