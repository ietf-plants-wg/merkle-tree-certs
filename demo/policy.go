package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type Policy struct {
	Version               DraftVersion
	Names                 map[string]PolicyIndex
	Cosigners             []*CosignerPublic
	Groups                []PolicyGroup
	RequirementsForAllCAs []PolicyIndex
	CAs                   map[string]*TrustedCA
}

type PolicyIndex struct {
	IsGroup bool
	Index   int
}

type PolicyGroup struct {
	Name    string
	Number  int
	Members []PolicyIndex
}

type TrustedCA struct {
	Certificate     *x509.Certificate
	CosignerIndex   int
	Requirements    []PolicyIndex
	RevokedRanges   []RevokedRange
	TrustedSubtrees []TrustedSubtree
}

func (ca *TrustedCA) FindTrustedSubtree(log uint16, start, end uint64) (HashValue, bool) {
	for _, t := range ca.TrustedSubtrees {
		if t.Log == log && t.Start == start && t.End == end {
			return t.Hash, true
		}
	}
	return HashValue{}, false
}

type RevokedRange struct {
	MinSerial, MaxSerial uint64
}

type TrustedSubtree struct {
	Log        uint16
	Start, End uint64
	Hash       HashValue
}

func caIDFromX509Name(name []byte) (TrustAnchorID, error) {
	s := cryptobyte.String(name)
	var dn, rdn, attr cryptobyte.String
	var attrOID asn1.ObjectIdentifier
	if !s.ReadASN1(&dn, cbasn1.SEQUENCE) ||
		!s.Empty() ||
		!dn.ReadASN1(&rdn, cbasn1.SET) ||
		!rdn.ReadASN1(&attr, cbasn1.SEQUENCE) ||
		!attr.ReadASN1ObjectIdentifier(&attrOID) {
		return nil, errors.New("malformed X.509 name")
	}
	if !attrOID.Equal(oidRDNATrustAnchorIDExperiment) {
		return nil, fmt.Errorf("unexpected X.509 name attribute %s", attrOID)
	}
	var utf8Val cryptobyte.String
	if !attr.ReadASN1(&utf8Val, cbasn1.UTF8String) || !attr.Empty() {
		return nil, errors.New("malformed trust anchor ID UTF8String")
	}
	id, ok := TrustAnchorIDFromString(string(utf8Val))
	if !ok {
		return nil, fmt.Errorf("invalid trust anchor ID string %q", string(utf8Val))
	}
	if !rdn.Empty() || !dn.Empty() {
		return nil, errors.New("extra attributes in X.509 name")
	}
	return id, nil
}

func isEmptyOrASN1Null(s cryptobyte.String) bool {
	return s.Empty() || bytes.Equal(s, []byte{0x05, 0x00})
}

func (p *Policy) AddCA(ca *x509.Certificate) error {
	caID, err := caIDFromX509Name(ca.RawSubject)
	if err != nil {
		return fmt.Errorf("failed to extract CA ID from subject: %w", err)
	}

	if p.CAs == nil {
		p.CAs = map[string]*TrustedCA{}
	}
	if _, ok := p.CAs[caID.String()]; ok {
		return fmt.Errorf("CA %s already defined", caID)
	}

	var caExt *pkix.Extension
	for i := range ca.Extensions {
		if ca.Extensions[i].Id.Equal(oidMTCCAExperiment) {
			caExt = &ca.Extensions[i]
			break
		}
	}
	if caExt == nil {
		return fmt.Errorf("CA certificate does not contain MTC CA extension")
	}

	extVal := cryptobyte.String(caExt.Value)
	var seq, logHashSeq, sigAlgSeq cryptobyte.String
	var logHashOID, sigAlgOID asn1.ObjectIdentifier
	minSerial, maxSerial := uint64(0), uint64(math.MaxUint64)
	if !extVal.ReadASN1(&seq, cbasn1.SEQUENCE) || !extVal.Empty() ||
		!seq.ReadASN1(&logHashSeq, cbasn1.SEQUENCE) ||
		!logHashSeq.ReadASN1ObjectIdentifier(&logHashOID) ||
		!seq.ReadASN1(&sigAlgSeq, cbasn1.SEQUENCE) ||
		!sigAlgSeq.ReadASN1ObjectIdentifier(&sigAlgOID) ||
		!seq.ReadASN1Integer(&minSerial) {
		return fmt.Errorf("malformed MTC CA extension")
	}
	if p.Version >= VersionPlants05 {
		if !seq.ReadASN1Integer(&maxSerial) {
			return fmt.Errorf("malformed MTC CA extension")
		}
	}
	if !seq.Empty() {
		return fmt.Errorf("malformed MTC CA extension")
	}

	if !logHashOID.Equal(oidSHA256) || !isEmptyOrASN1Null(logHashSeq) {
		return errors.New("unsupported log hash algorithm")
	}

	var sigAlg SignatureAlgorithm
	switch {
	case sigAlgOID.Equal(oidECDSAWithSHA256) && sigAlgSeq.Empty():
		sigAlg = SignatureAlgorithmP256WithSHA256
	case sigAlgOID.Equal(oidECDSAWithSHA384) && sigAlgSeq.Empty():
		sigAlg = SignatureAlgorithmP384WithSHA384
	case sigAlgOID.Equal(oidEd25519) && sigAlgSeq.Empty():
		sigAlg = SignatureAlgorithmEd25519
	case sigAlgOID.Equal(oidMLDSA44) && sigAlgSeq.Empty():
		sigAlg = SignatureAlgorithmMLDSA44
	case sigAlgOID.Equal(oidMLDSA65) && sigAlgSeq.Empty():
		sigAlg = SignatureAlgorithmMLDSA65
	case sigAlgOID.Equal(oidMLDSA87) && sigAlgSeq.Empty():
		sigAlg = SignatureAlgorithmMLDSA87
	default:
		return errors.New("unknown signature algorithm in CA extension")
	}

	if err := p.AddCosigner(caID, sigAlg, ca.RawSubjectPublicKeyInfo); err != nil {
		return fmt.Errorf("failed to register CA cosigner: %w", err)
	}

	caEntry := &TrustedCA{
		Certificate:   ca,
		CosignerIndex: len(p.Cosigners) - 1,
	}
	p.CAs[caID.String()] = caEntry
	if minSerial > 0 {
		caEntry.RevokedRanges = append(caEntry.RevokedRanges, RevokedRange{0, minSerial - 1})
	}
	if maxSerial < math.MaxUint64 {
		caEntry.RevokedRanges = append(caEntry.RevokedRanges, RevokedRange{maxSerial + 1, math.MaxUint64})
	}

	return nil
}

func (p *Policy) AddCosigner(id TrustAnchorID, sigAlg SignatureAlgorithm, spki []byte) error {
	if p.Names == nil {
		p.Names = map[string]PolicyIndex{}
	}
	if _, ok := p.Names[id.String()]; ok {
		return fmt.Errorf("cosigner %q already defined", id.String())
	}
	pubKey, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return fmt.Errorf("failed to parse SPKI: %w", err)
	}
	cosigner := &CosignerPublic{
		Version:            p.Version,
		ID:                 id,
		SignatureAlgorithm: sigAlg,
		PublicKey:          pubKey,
	}
	p.Cosigners = append(p.Cosigners, cosigner)
	p.Names[id.String()] = PolicyIndex{IsGroup: false, Index: len(p.Cosigners) - 1}
	return nil
}

func (p *Policy) AddGroup(name string, num int, members []string) error {
	if p.Names == nil {
		p.Names = map[string]PolicyIndex{}
	}
	if _, exists := p.Names[name]; exists {
		return fmt.Errorf("group or cosigner %q already defined", name)
	}
	var memberIndices []PolicyIndex
	for _, m := range members {
		idx, ok := p.Names[m]
		if !ok {
			return fmt.Errorf("unknown member %q in group %q", m, name)
		}
		memberIndices = append(memberIndices, idx)
	}
	groupIdx := len(p.Groups)
	p.Groups = append(p.Groups, PolicyGroup{
		Name:    name,
		Number:  num,
		Members: memberIndices,
	})
	p.Names[name] = PolicyIndex{IsGroup: true, Index: groupIdx}
	return nil
}

func (p *Policy) RequireCosignersForCA(ca TrustAnchorID, name string) error {
	idx, ok := p.Names[name]
	if !ok {
		return fmt.Errorf("unknown cosigner or group %q", name)
	}
	caEntry, ok := p.CAs[ca.String()]
	if !ok {
		return fmt.Errorf("unknown CA %s", ca)
	}
	caEntry.Requirements = append(caEntry.Requirements, idx)
	return nil
}

func (p *Policy) RequireCosignersForAllCAs(name string) error {
	idx, ok := p.Names[name]
	if !ok {
		return fmt.Errorf("unknown cosigner or group %q", name)
	}
	p.RequirementsForAllCAs = append(p.RequirementsForAllCAs, idx)
	return nil
}

func (p *Policy) RevokeRange(ca TrustAnchorID, minSerial, maxSerial uint64) error {
	if minSerial > maxSerial {
		return fmt.Errorf("minSerial (%d) > maxSerial (%d)", minSerial, maxSerial)
	}
	caEntry, ok := p.CAs[ca.String()]
	if !ok {
		return fmt.Errorf("unknown CA %s", ca)
	}
	caEntry.RevokedRanges = append(caEntry.RevokedRanges, RevokedRange{minSerial, maxSerial})
	return nil
}

func (p *Policy) AddTrustedSubtree(ca TrustAnchorID, log uint16, start, end uint64, hash HashValue) error {
	if !IsValidSubtree(start, end) {
		return fmt.Errorf("invalid subtree [%d, %d)", start, end)
	}
	caEntry, ok := p.CAs[ca.String()]
	if !ok {
		return fmt.Errorf("unknown CA %s", ca)
	}
	caEntry.TrustedSubtrees = append(caEntry.TrustedSubtrees, TrustedSubtree{
		Log:   log,
		Start: start,
		End:   end,
		Hash:  hash,
	})
	return nil
}

func (p *Policy) NameForIndex(idx PolicyIndex) string {
	if idx.IsGroup {
		return p.Groups[idx.Index].Name
	}
	return p.Cosigners[idx.Index].ID.String()
}

type PolicyResult struct {
	Cosigners []bool
	Groups    []bool
}

func (r *PolicyResult) Satisfied(idx PolicyIndex) bool {
	if idx.IsGroup {
		return r.Groups[idx.Index]
	}
	return r.Cosigners[idx.Index]
}

func (p *Policy) EvaluateGroups(cosigners []bool) PolicyResult {
	ret := PolicyResult{
		Cosigners: cosigners,
		Groups:    make([]bool, len(p.Groups)),
	}
	for i, g := range p.Groups {
		count := 0
		for _, m := range g.Members {
			if ret.Satisfied(m) {
				count++
			}
		}
		ret.Groups[i] = count >= g.Number
	}
	return ret
}
