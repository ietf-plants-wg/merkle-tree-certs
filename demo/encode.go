package main

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/bits"
	"slices"
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

	oidMTCProofExperiment          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}
	oidRDNATrustAnchorIDExperiment = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	oidMTCCAExperiment             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 2}

	oidAlgUnsigned  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 36}
	oidRDNAUnsigned = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 1}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidMLDSA44         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
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
		alg.AddASN1ObjectIdentifier(oidMTCProofExperiment)
	})
}

func addUnsignedSigAlg(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
		alg.AddASN1ObjectIdentifier(oidAlgUnsigned)
	})
}

func addX509Name(b *cryptobyte.Builder, id TrustAnchorID) {
	b.AddASN1(cbasn1.SEQUENCE, func(dn *cryptobyte.Builder) {
		dn.AddASN1(cbasn1.SET, func(rdn *cryptobyte.Builder) {
			rdn.AddASN1(cbasn1.SEQUENCE, func(attr *cryptobyte.Builder) {
				attr.AddASN1ObjectIdentifier(oidRDNATrustAnchorIDExperiment)
				attr.AddASN1(cbasn1.UTF8String, func(val *cryptobyte.Builder) {
					val.AddBytes([]byte(id.String()))
				})
			})
		})
	})
}

func addUnsignedX509NamePlaceholder(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(dn *cryptobyte.Builder) {
		dn.AddASN1(cbasn1.SET, func(rdn *cryptobyte.Builder) {
			rdn.AddASN1(cbasn1.SEQUENCE, func(attr *cryptobyte.Builder) {
				attr.AddASN1ObjectIdentifier(oidRDNAUnsigned)
				attr.AddASN1(cbasn1.UTF8String, func(val *cryptobyte.Builder) {})
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

func addValidity(b *cryptobyte.Builder, config *CertConfigBase) {
	b.AddASN1(cbasn1.SEQUENCE, func(val *cryptobyte.Builder) {
		addX509Time(val, config.NotBefore)
		addX509Time(val, config.NotAfter)
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

type mtcCAInfo struct {
	cosigner  *Cosigner
	minSerial uint64
}

func addExtensions(b *cryptobyte.Builder, config *CertConfigBase, mtcCA *mtcCAInfo) {
	hasKeyUsage := config.KeyUsage != 0
	hasExtKeyUsage := len(config.ExtKeyUsage) != 0
	hasSubjectAltName := len(config.DNSNames) != 0
	hasBasicConstraints := config.IsCA != nil || config.MaxPathLen != nil
	if !hasKeyUsage && !hasExtKeyUsage && !hasSubjectAltName && !hasBasicConstraints && mtcCA == nil {
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
					b[0] = bits.Reverse8(byte(config.KeyUsage))
					b[1] = bits.Reverse8(byte(config.KeyUsage >> 8))
					// If the final byte is all zeros, skip it.
					var ku asn1.BitString
					if b[1] == 0 {
						ku.Bytes = b[:1]
					} else {
						ku.Bytes = b[:]
					}
					ku.BitLength = bits.Len16(uint16(config.KeyUsage))
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
						for _, eku := range config.ExtKeyUsage {
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
						for _, dns := range config.DNSNames {
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
						if config.IsCA != nil && *config.IsCA {
							bc.AddASN1Boolean(true)
						}
						if config.MaxPathLen != nil {
							bc.AddASN1Int64(int64(*config.MaxPathLen))
						}
					})
				})
			})
		}

		if mtcCA != nil {
			exts.AddASN1(cbasn1.SEQUENCE, func(ext *cryptobyte.Builder) {
				ext.AddASN1ObjectIdentifier(oidMTCCAExperiment)
				ext.AddASN1Boolean(true)
				ext.AddASN1(cbasn1.OCTET_STRING, func(extVal *cryptobyte.Builder) {
					extVal.AddASN1(cbasn1.SEQUENCE, func(seq *cryptobyte.Builder) {
						seq.AddASN1(cbasn1.SEQUENCE, func(logHash *cryptobyte.Builder) {
							logHash.AddASN1ObjectIdentifier(oidSHA256)
						})
						seq.AddASN1(cbasn1.SEQUENCE, func(sigAlg *cryptobyte.Builder) {
							switch mtcCA.cosigner.SignatureAlgorithm {
							case SignatureAlgorithmP256WithSHA256:
								sigAlg.AddASN1ObjectIdentifier(oidECDSAWithSHA256)
							case SignatureAlgorithmP384WithSHA384:
								sigAlg.AddASN1ObjectIdentifier(oidECDSAWithSHA384)
							case SignatureAlgorithmEd25519:
								sigAlg.AddASN1ObjectIdentifier(oidEd25519)
							case SignatureAlgorithmMLDSA44:
								sigAlg.AddASN1ObjectIdentifier(oidMLDSA44)
							case SignatureAlgorithmMLDSA65:
								sigAlg.AddASN1ObjectIdentifier(oidMLDSA65)
							case SignatureAlgorithmMLDSA87:
								sigAlg.AddASN1ObjectIdentifier(oidMLDSA87)
							default:
								panic(fmt.Errorf("unknown signature algorithm %s", mtcCA.cosigner.SignatureAlgorithm))
							}
						})
						seq.AddASN1Uint64(mtcCA.minSerial)
					})
				})
			})
		}
	})
}

func AddTBSCertificate(b *cryptobyte.Builder, issuer TrustAnchorID, serial uint64, entry *EntryConfig) {
	b.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
		addX509V3Version(tbs)
		tbs.AddASN1Uint64(serial)
		addMTCProofSigAlg(tbs)
		addX509Name(tbs, issuer)
		addValidity(tbs, &entry.CertConfigBase)
		addSubject(tbs, entry)
		tbs.AddBytes(entry.PublicKey)
		addExtensions(tbs, &entry.CertConfigBase, nil)
	})
}

// addEmptyMTCEntryExtensions adds an empty extensions field to b if the
// version is at least draft-plants-04.
func addEmptyMTCEntryExtensions(b *cryptobyte.Builder, version DraftVersion) {
	if version >= VersionPlants04 {
		b.AddUint16LengthPrefixed(func(_ *cryptobyte.Builder) {})
	}
}

func MarshalNullEntry(version DraftVersion) []byte {
	b := cryptobyte.NewBuilder(nil)
	// Starting in draft 04, MerkleTreeCertEntry is prefixed with a
	// MerkleTreeCertEntryExtension vector.
	addEmptyMTCEntryExtensions(b, version)
	b.AddUint16(entryTypeNull)
	out, err := b.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}

func MarshalTBSCertificateLogEntry(version DraftVersion, issuer TrustAnchorID, entry *EntryConfig) ([]byte, error) {
	if entry.Null {
		return MarshalNullEntry(version), nil
	}

	marshalContents := func(tbs *cryptobyte.Builder) {
		addX509V3Version(tbs)
		addX509Name(tbs, issuer)
		addValidity(tbs, &entry.CertConfigBase)
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
		addExtensions(tbs, &entry.CertConfigBase, nil)
	}
	b := cryptobyte.NewBuilder(nil)
	addEmptyMTCEntryExtensions(b, version)
	b.AddUint16(entryTypeTBSCert)
	// Starting draft-davidben-10, the SEQUENCE wrapper is omitted.
	if version >= VersionDavidben10 {
		marshalContents(b)
	} else {
		b.AddASN1(cbasn1.SEQUENCE, marshalContents)
	}
	return b.Bytes()
}

func LogID(config *CAConfig) TrustAnchorID {
	if config.Version < VersionPlants04 {
		// Prior to plants-04, each CA only had one log.
		return config.ID
	}
	logID := appendBase128(slices.Clip(config.ID), 0)
	logID = appendBase128(logID, uint32(config.LogNumber))
	return logID
}

func CreateCertificate(config *CAConfig, issuanceLog *MerkleTree, cosigners []*Cosigner, entry *EntryConfig, certConfig *CertificateConfig, index, start, end int) ([]byte, error) {
	if entry.Null {
		return nil, errors.New("cannot construct certificate for null entry")
	}

	logID := LogID(config)
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(cert *cryptobyte.Builder) {
		serial := uint64(index)
		if config.Version >= VersionPlants04 {
			if serial > 1<<48-1 {
				cert.SetError(fmt.Errorf("invalid serial: %d", index))
				return
			}
			serial |= uint64(config.LogNumber) << 48
		}
		AddTBSCertificate(cert, config.ID, serial, entry)
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
			addEmptyMTCEntryExtensions(certSig, config.Version)
			if config.Version >= VersionPlants04 {
				certSig.AddUint48(uint64(start))
				certSig.AddUint48(uint64(end))
			} else {
				certSig.AddUint64(uint64(start))
				certSig.AddUint64(uint64(end))
			}
			certSig.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(proof) })
			certSig.AddUint16LengthPrefixed(func(cosigs *cryptobyte.Builder) {
				// plants-04 canonicalizes the cosigner order.
				if !certConfig.DontSortCosigners && config.Version >= VersionPlants04 {
					cosigners = slices.SortedFunc(slices.Values(cosigners), func(a, b *Cosigner) int {
						return cmp.Or(
							cmp.Compare(len(a.ID), len(b.ID)),
							bytes.Compare(a.ID, b.ID),
						)
					})
				}
				for _, cosigner := range cosigners {
					cosig, err := cosigner.Sign(logID, start, end, &subtree)
					if err != nil {
						cosigs.SetError(err)
						return
					}
					addTrustAnchorID(cosigs, cosigner.ID)
					cosigs.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(cosig) })
				}
			})
			if certConfig.UnusedBit {
				if sig, err := certSig.Bytes(); err == nil && (len(sig) == 0 || sig[len(sig)-1]&1 != 0) {
					certSig.SetError(errors.New("last bit in signature with not zero, unable to encode as unused"))
					return
				}
			}
		})
	})
	return b.Bytes()
}

func CreateCACertificate(config *CAConfig, cosigner *Cosigner) ([]byte, error) {
	pub := cosigner.Signer.Public()
	spki, err := marshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(cert *cryptobyte.Builder) {
		cert.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
			addX509V3Version(tbs)
			tbs.AddASN1Uint64(1)
			addUnsignedSigAlg(tbs)
			addUnsignedX509NamePlaceholder(tbs) // No issuer
			addValidity(tbs, &config.CACert.CertConfigBase)
			addX509Name(tbs, config.ID) // Subject
			tbs.AddBytes(spki)
			addExtensions(tbs, &config.CACert.CertConfigBase, &mtcCAInfo{
				cosigner:  cosigner,
				minSerial: config.CACert.MinSerial,
			})
		})
		addUnsignedSigAlg(cert)
		cert.AddASN1BitString(nil)
	})
	return b.Bytes()
}
