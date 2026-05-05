package main

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/bits"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	entryTypeNull    = 0
	entryTypeTBSCert = 1
)

var (
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}

	oidMTCProofExperimental        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}
	oidRDNATrustAnchorIDExperiment = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
)

func addASN1ImplicitString(bb *cryptobyte.Builder, tag cbasn1.Tag, b []byte) {
	bb.AddASN1(tag, func(child *cryptobyte.Builder) { child.AddBytes(b) })
}

func addASN1ExplicitTag(bb *cryptobyte.Builder, outerTag, innerTag cbasn1.Tag, cb func(*cryptobyte.Builder)) {
	bb.AddASN1(outerTag.Constructed().ContextSpecific(), func(child *cryptobyte.Builder) {
		child.AddASN1(innerTag, cb)
	})
}

func addX509V3Version(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(vers *cryptobyte.Builder) {
		vers.AddASN1Uint64(2) // v3
	})
}

func addMTCProofSigAlg(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
		alg.AddASN1ObjectIdentifier(oidMTCProofExperimental)
	})
}

func addIssuer(b *cryptobyte.Builder, issuer TrustAnchorID) {
	b.AddASN1(cbasn1.SEQUENCE, func(dn *cryptobyte.Builder) {
		dn.AddASN1(cbasn1.SET, func(rdn *cryptobyte.Builder) {
			rdn.AddASN1(cbasn1.SEQUENCE, func(attr *cryptobyte.Builder) {
				attr.AddASN1ObjectIdentifier(oidRDNATrustAnchorIDExperiment)
				attr.AddASN1(cbasn1.UTF8String, func(val *cryptobyte.Builder) {
					val.AddBytes([]byte(issuer.String()))
				})
			})
		})
	})
}

func addX509Time(b *cryptobyte.Builder, t time.Time) {
	t = t.UTC()
	if y := t.Year(); 1950 <= y && y <= 2049 {
		b.AddASN1UTCTime(t)
	} else {
		b.AddASN1GeneralizedTime(t)
	}
}

func addValidity(b *cryptobyte.Builder, entry *EntryConfig) {
	b.AddASN1(cbasn1.SEQUENCE, func(val *cryptobyte.Builder) {
		addX509Time(val, entry.NotBefore)
		addX509Time(val, entry.NotAfter)
	})
}

func addSubject(b *cryptobyte.Builder, entry *EntryConfig) {
	p := pkix.Name{
		Country:            entry.Subject.Country,
		Organization:       entry.Subject.Organization,
		OrganizationalUnit: entry.Subject.OrganizationalUnit,
		Locality:           entry.Subject.Locality,
		Province:           entry.Subject.Province,
		StreetAddress:      entry.Subject.StreetAddress,
		PostalCode:         entry.Subject.PostalCode,
		SerialNumber:       entry.Subject.SerialNumber,
		CommonName:         entry.Subject.CommonName,
	}
	b.MarshalASN1(p.ToRDNSequence())
}

func addExtensions(b *cryptobyte.Builder, entry *EntryConfig) {
	hasKeyUsage := entry.KeyUsage != 0
	hasExtKeyUsage := len(entry.ExtKeyUsage) != 0
	hasSubjectAltName := len(entry.DNSNames) != 0
	hasBasicConstraints := entry.IsCA != nil || entry.MaxPathLen != nil
	if !hasKeyUsage && !hasExtKeyUsage && !hasSubjectAltName && !hasBasicConstraints {
		return
	}

	addASN1ExplicitTag(b, 3, cbasn1.SEQUENCE, func(exts *cryptobyte.Builder) {
		if hasKeyUsage {
			exts.AddASN1(cbasn1.SEQUENCE, func(ext *cryptobyte.Builder) {
				ext.AddASN1ObjectIdentifier(oidKeyUsage)
				ext.AddASN1Boolean(true) // critical
				ext.AddASN1(cbasn1.OCTET_STRING, func(extVal *cryptobyte.Builder) {
					var b [2]byte
					// DER orders the bits from most to least significant.
					b[0] = bits.Reverse8(byte(entry.KeyUsage))
					b[1] = bits.Reverse8(byte(entry.KeyUsage >> 8))
					// If the final byte is all zeros, skip it.
					var ku asn1.BitString
					if b[1] == 0 {
						ku.Bytes = b[:1]
					} else {
						ku.Bytes = b[:]
					}
					ku.BitLength = bits.Len16(uint16(entry.KeyUsage))
					der, err := asn1.Marshal(ku)
					if err != nil {
						extVal.SetError(err)
					} else {
						extVal.AddBytes(der)
					}
				})
			})
		}

		if hasExtKeyUsage {
			exts.AddASN1(cbasn1.SEQUENCE, func(ext *cryptobyte.Builder) {
				ext.AddASN1ObjectIdentifier(oidExtKeyUsage)
				ext.AddASN1Boolean(true) // critical
				ext.AddASN1(cbasn1.OCTET_STRING, func(extVal *cryptobyte.Builder) {
					extVal.AddASN1(cbasn1.SEQUENCE, func(ekus *cryptobyte.Builder) {
						for _, eku := range entry.ExtKeyUsage {
							ekus.AddASN1ObjectIdentifier(asn1.ObjectIdentifier(eku))
						}
					})
				})
			})
		}

		if hasSubjectAltName {
			exts.AddASN1(cbasn1.SEQUENCE, func(ext *cryptobyte.Builder) {
				ext.AddASN1ObjectIdentifier(oidSubjectAltName)
				ext.AddASN1Boolean(true) // critical, needed if the subject is empty
				ext.AddASN1(cbasn1.OCTET_STRING, func(extVal *cryptobyte.Builder) {
					extVal.AddASN1(cbasn1.SEQUENCE, func(names *cryptobyte.Builder) {
						for _, dns := range entry.DNSNames {
							addASN1ImplicitString(names, cbasn1.Tag(2).ContextSpecific(), []byte(dns))
						}
					})
				})
			})
		}

		if hasBasicConstraints {
			exts.AddASN1(cbasn1.SEQUENCE, func(ext *cryptobyte.Builder) {
				ext.AddASN1ObjectIdentifier(oidBasicConstraints)
				ext.AddASN1Boolean(true)
				ext.AddASN1(cbasn1.OCTET_STRING, func(extVal *cryptobyte.Builder) {
					extVal.AddASN1(cbasn1.SEQUENCE, func(bc *cryptobyte.Builder) {
						if entry.IsCA != nil && *entry.IsCA {
							bc.AddASN1Boolean(true)
						}
						if entry.MaxPathLen != nil {
							bc.AddASN1Int64(int64(*entry.MaxPathLen))
						}
					})
				})
			})
		}
	})
}

func AddTBSCertificate(b *cryptobyte.Builder, issuer TrustAnchorID, serial int, entry *EntryConfig) {
	b.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
		addX509V3Version(tbs)
		tbs.AddASN1Int64(int64(serial))
		addMTCProofSigAlg(tbs)
		addIssuer(tbs, issuer)
		addValidity(tbs, entry)
		addSubject(tbs, entry)
		tbs.AddBytes(entry.PublicKey)
		addExtensions(tbs, entry)
	})
}

func MarshalNullEntry() []byte {
	return []byte{byte(entryTypeNull >> 8), byte(entryTypeNull)}
}

func MarshalTBSCertificateLogEntry(version DraftVersion, issuer TrustAnchorID, entry *EntryConfig) ([]byte, error) {
	marshalContents := func(tbs *cryptobyte.Builder) {
		addX509V3Version(tbs)
		addIssuer(tbs, issuer)
		addValidity(tbs, entry)
		addSubject(tbs, entry)
		// Starting draft-plants-02, the public key algorithm is included in
		// the entry.
		if version >= VersionPlants02 {
			spki := cryptobyte.String(entry.PublicKey)
			var seq, alg cryptobyte.String
			if !spki.ReadASN1(&seq, cbasn1.SEQUENCE) ||
				!spki.Empty() ||
				!seq.ReadASN1Element(&alg, cbasn1.SEQUENCE) {
				tbs.SetError(errors.New("could not parse public key"))
				return
			}
			tbs.AddBytes(alg)
		}
		tbs.AddASN1(cbasn1.OCTET_STRING, func(spkiHash *cryptobyte.Builder) {
			h := sha256.Sum256(entry.PublicKey)
			spkiHash.AddBytes(h[:])
		})
		addExtensions(tbs, entry)
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(entryTypeTBSCert)
	// Starting draft-davidben-10, the SEQUENCE wrapper is omitted.
	if version >= VersionDavidben10 {
		marshalContents(b)
	} else {
		b.AddASN1(cbasn1.SEQUENCE, marshalContents)
	}
	return b.Bytes()
}

func CreateCertificate(issuanceLog *MerkleTree, issuer TrustAnchorID, cosigners []*CosignerConfig, entry *EntryConfig, certConfig *CertificateConfig, index, start, end int) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(cert *cryptobyte.Builder) {
		AddTBSCertificate(cert, issuer, index, entry)
		addMTCProofSigAlg(cert)
		cert.AddASN1(cbasn1.BIT_STRING, func(certSig *cryptobyte.Builder) {
			proof, err := issuanceLog.SubtreeInclusionProof(index, start, end)
			if err != nil {
				certSig.SetError(err)
				return
			}
			if certConfig.BitFlipProof {
				if len(proof) == 0 {
					certSig.SetError(errors.New("could not flip bit in empty proof"))
					return
				}
				proof[0] ^= 1
			}
			subtree, err := issuanceLog.SubtreeHash(start, end)
			if err != nil {
				certSig.SetError(err)
				return
			}

			if certConfig.UnusedBit {
				certSig.AddBytes([]byte{1})
			} else {
				certSig.AddBytes([]byte{0})
			}
			certSig.AddUint64(uint64(start))
			certSig.AddUint64(uint64(end))
			certSig.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(proof) })
			certSig.AddUint16LengthPrefixed(func(cosigs *cryptobyte.Builder) {
				for _, cosigner := range cosigners {
					cosig, err := Cosign(cosigner, issuer, start, end, &subtree)
					if err != nil {
						cosigs.SetError(err)
						return
					}
					addTrustAnchorID(cosigs, cosigner.CosignerID)
					cosigs.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(cosig) })
				}
			})
			if certConfig.UnusedBit {
				if sig, err := certSig.Bytes(); err == nil && len(sig) == 0 || sig[len(sig)-1]&1 != 0 {
					certSig.SetError(errors.New("last bit in signature with not zero, unable to encode as unused"))
					return
				}
			}
		})
	})
	return b.Bytes()
}
