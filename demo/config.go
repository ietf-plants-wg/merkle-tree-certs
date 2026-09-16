package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	oidServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
)

type DraftVersion int

// Support versions for as long as it is easy to support and useful. If we need
// to remove one, older versions of the demo tool are always available.
const (
	VersionDavidben09 DraftVersion = iota
	VersionDavidben10
	VersionPlants01
	VersionPlants02
	VersionPlants04
	VersionPlants05
	VersionPlants06
)

func (v DraftVersion) String() string {
	switch v {
	case VersionDavidben09:
		return "davidben-09"
	case VersionDavidben10:
		return "davidben-10"
	case VersionPlants01:
		return "plants-01"
	case VersionPlants02:
		return "plants-02"
	case VersionPlants04:
		return "plants-04"
	case VersionPlants05:
		return "plants-05"
	case VersionPlants06:
		return "plants-06"
	}
	panic(fmt.Sprintf("unknown version %d", v))
}

func (v *DraftVersion) UnmarshalText(text []byte) error {
	var ok bool
	*v, ok = DraftVersionFromString(string(text))
	if !ok {
		return fmt.Errorf("unknown version %q", text)
	}
	return nil
}

func DraftVersionFromString(s string) (v DraftVersion, ok bool) {
	switch s {
	case "davidben-09":
		return VersionDavidben09, true
	case "davidben-10":
		return VersionDavidben10, true
	case "plants-01":
		return VersionPlants01, true
	case "plants-02":
		return VersionPlants02, true
	case "plants-04":
		return VersionPlants04, true
	case "plants-05":
		return VersionPlants05, true
	case "plants-06":
		return VersionPlants06, true

	default:
		return 0, false
	}
}

type SignatureAlgorithm int

const (
	SignatureAlgorithmP256WithSHA256 SignatureAlgorithm = iota
	SignatureAlgorithmP384WithSHA384
	SignatureAlgorithmEd25519
	SignatureAlgorithmMLDSA44
	SignatureAlgorithmMLDSA65
	SignatureAlgorithmMLDSA87
)

func SignatureAlgorithmFromString(s string) (SignatureAlgorithm, bool) {
	switch s {
	case "ecdsa_p256_sha256":
		return SignatureAlgorithmP256WithSHA256, true
	case "ecdsa_p384_sha384":
		return SignatureAlgorithmP384WithSHA384, true
	case "ed25519":
		return SignatureAlgorithmEd25519, true
	case "mldsa44":
		return SignatureAlgorithmMLDSA44, true
	case "mldsa65":
		return SignatureAlgorithmMLDSA65, true
	case "mldsa87":
		return SignatureAlgorithmMLDSA87, true

	}
	return 0, false
}

func (s SignatureAlgorithm) String() string {
	switch s {
	case SignatureAlgorithmP256WithSHA256:
		return "ecdsa_p256_sha256"
	case SignatureAlgorithmP384WithSHA384:
		return "ecdsa_p384_sha384"
	case SignatureAlgorithmEd25519:
		return "ed25519"
	case SignatureAlgorithmMLDSA44:
		return "mldsa44"
	case SignatureAlgorithmMLDSA65:
		return "mldsa65"
	case SignatureAlgorithmMLDSA87:
		return "mldsa87"
	default:
		panic(fmt.Sprintf("unexpected SignatureAlgorithm: %#v", s))
	}
}

func (s *SignatureAlgorithm) UnmarshalText(text []byte) error {
	var ok bool
	*s, ok = SignatureAlgorithmFromString(string(text))
	if !ok {
		return fmt.Errorf("invalid signature algorithm: %q", text)
	}
	return nil
}

type CAConfig struct {
	Version   DraftVersion
	ID        TrustAnchorID
	LogNumber uint16
	Cosigners []CosignerConfig
	CACert    CACertConfig
	Entries   []EntryConfig
}

type CosignerConfig struct {
	CosignerID         TrustAnchorID
	SignatureAlgorithm SignatureAlgorithm
	PrivateKey         []byte
}

type SerialConfig struct {
	Log   uint16
	Index uint64
}

type CACertConfig struct {
	CertConfigBase
	MinSerial, MaxSerial SerialConfig
}

type CertConfigBase struct {
	NotBefore, NotAfter time.Time
	DNSNames            []string
	KeyUsage            KeyUsageConfig
	ExtKeyUsage         []ExtKeyUsageConfig
	IsCA                *bool
	MaxPathLen          *int64
}

type EntryConfig struct {
	// A number of times to repeat this entry.
	Repeat int
	// Null, if true, causes this to be a null entry. The certificate fields
	// below are ignored.
	Null      bool
	Subject   SubjectConfig
	PublicKey []byte
	CertConfigBase
	// A list of checkpoint sequence names that end at this entry. Every
	// checkpoint sequence implicitly starts at 0.
	Checkpoints []string
	// A list of certificates to generate from this entry.
	Certificates []CertificateConfig
}

type SubjectConfig struct {
	Country, Organization, OrganizationalUnit []string
	Locality, Province                        []string
	StreetAddress, PostalCode                 []string
	SerialNumber, CommonName                  string
}

type CertificateConfig struct {
	// At most one of SubtreeStart/SubtreeEnd and Checkpoint may be specified.
	// If SubtreeStart/SubtreeEnd is specified, that subtree is used. (Entries
	// are zero-indexed, but there is always a null entry at zero, so they are
	// effectively one-indexed.)
	// If Checkpoint is used, the named checkpoint sequence is used.
	SubtreeStart, SubtreeEnd uint64
	Checkpoint               string
	// Must refer to a cosigner defined in the CAConfig.
	Cosigners []TrustAnchorID
	// BitFlipProof, if true, flips a bit in the inclusion proof.
	BitFlipProof bool
	// UnusedBit, if true, encodes the last bit in the signatureValue, which
	// must be zero, as unused. This makes the signatureValue a non-whole
	// number of bytes.
	UnusedBit bool
	// DontSortCosigners, if true, skips sorting the cosigners and includes
	// signatures in the specified order.
	DontSortCosigners bool
	// OverrideSignatureAlgorithm, if not empty, overrides the outer signature
	// algorithm with the specified byte string.
	OverrideSignatureAlgorithm []byte
	// OverrideSignatureAlgorithm, if not empty, overrides the TBSCertificate
	// signature algorithm with the specified byte string.
	OverrideTBSSignatureAlgorithm   []byte
	OverrideCertificatePropertyList *CertificatePropertyList
}

type CertificatePropertyList struct {
	TrustAnchorID          TrustAnchorID
	TrustAnchorGroups      []TrustAnchorIDPattern
	TrustAnchorNegotiation bool
}

func parseBase128(in []byte) (ret uint32, rest []byte, ok bool) {
	rest = in
	if len(rest) == 0 {
		return
	}
	if rest[0] == 0x80 {
		return // Not minimally-encoded
	}
	for {
		if len(rest) == 0 || (ret<<7)>>7 != ret {
			// Input too small or overflow.
			return
		}
		b := rest[0]
		ret <<= 7
		ret |= uint32(b & 0x7f)
		rest = rest[1:]
		if b&0x80 == 0 {
			ok = true
			return
		}
	}
}

func appendBase128(dst []byte, v uint32) []byte {
	// Count how many bytes are needed.
	var l int
	for n := v; n != 0; n >>= 7 {
		l++
	}
	// Special-case: zero is encoded with one, not zero bytes.
	if v == 0 {
		l = 1
	}
	for ; l > 0; l-- {
		b := byte(v>>uint(7*(l-1))) & 0x7f
		if l > 1 {
			b |= 0x80
		}
		dst = append(dst, b)
	}
	return dst
}

type TrustAnchorID []byte

func TrustAnchorIDFromString(s string) (t TrustAnchorID, ok bool) {
	for _, part := range strings.Split(s, ".") {
		v, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return
		}
		t = appendBase128(t, uint32(v))
	}
	if len(t) == 0 {
		return
	}
	ok = true
	return
}

func (t TrustAnchorID) String() string {
	if len(t) == 0 {
		return fmt.Sprintf("<invalid: %x>", []byte(t))
	}
	rest := t
	var s strings.Builder
	for len(rest) != 0 {
		var v uint32
		var ok bool
		v, rest, ok = parseBase128(rest)
		if !ok {
			return fmt.Sprintf("<invalid: %x>", []byte(t))
		}
		if s.Len() != 0 {
			s.WriteByte('.')
		}
		fmt.Fprintf(&s, "%d", v)
	}
	return s.String()
}

func (t *TrustAnchorID) UnmarshalText(text []byte) error {
	var ok bool
	*t, ok = TrustAnchorIDFromString(string(text))
	if !ok {
		return fmt.Errorf("invalid trust anchor ID: %q", text)
	}
	return nil
}

type TrustAnchorIDPattern []byte

func appendPatternRange(pattern TrustAnchorIDPattern, min, max uint32) TrustAnchorIDPattern {
	pattern = appendBase128(pattern, min)
	pattern = appendBase128(pattern, max)
	return pattern
}

func appendPatternRangeWithInfinity(pattern TrustAnchorIDPattern, min uint32) TrustAnchorIDPattern {
	pattern = appendBase128(pattern, min)
	pattern = append(pattern, 0x80)
	return pattern
}

func TrustAnchorIDPatternFromString(s string) (t TrustAnchorIDPattern, ok bool) {
	for _, part := range strings.Split(s, ".") {
		if part != "" && part[0] == '{' && part[len(part)-1] == '}' {
			part = part[1 : len(part)-1]
			minMax := strings.SplitN(part, "-", 2)
			if len(minMax) != 2 {
				return
			}
			min, err := strconv.ParseUint(minMax[0], 10, 32)
			if err != nil {
				return
			}
			if minMax[1] == "" {
				t = appendPatternRangeWithInfinity(t, uint32(min))
			} else {
				max, err := strconv.ParseUint(minMax[1], 10, 32)
				if err != nil {
					return
				}
				t = appendPatternRange(t, uint32(min), uint32(max))
			}
		} else {
			v, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return
			}
			t = appendPatternRange(t, uint32(v), uint32(v))
		}
	}
	if len(t) == 0 {
		return
	}
	ok = true
	return
}

func (t TrustAnchorIDPattern) String() string {
	if len(t) == 0 {
		return fmt.Sprintf("<invalid: %x>", []byte(t))
	}
	var s strings.Builder
	rest := t
	for len(rest) != 0 {
		var min, max uint32
		var ok bool
		if s.Len() != 0 {
			s.WriteByte('.')
		}
		min, rest, ok = parseBase128(rest)
		if !ok {
			return fmt.Sprintf("<invalid: %x>", []byte(t))
		}
		if len(rest) > 0 && rest[0] == 0x80 {
			fmt.Fprintf(&s, "{%d-}", min)
			rest = rest[1:]
		} else {
			max, rest, ok = parseBase128(rest)
			if !ok {
				return fmt.Sprintf("<invalid: %x>", []byte(t))
			}
			if min == max {
				fmt.Fprintf(&s, "%d", min)
			} else {
				fmt.Fprintf(&s, "{%d-%d}", min, max)
			}
		}

	}
	return s.String()
}

func (t *TrustAnchorIDPattern) UnmarshalText(text []byte) error {
	var ok bool
	*t, ok = TrustAnchorIDPatternFromString(string(text))
	if !ok {
		return fmt.Errorf("invalid trust anchor ID pattern: %q", text)
	}
	return nil
}

func TrustAnchorIDToPattern(id TrustAnchorID) TrustAnchorIDPattern {
	pattern := make([]byte, 0, len(id)*2)
	rest := id
	for len(rest) != 0 {
		var v uint32
		var ok bool
		v, rest, ok = parseBase128(rest)
		if !ok {
			panic(fmt.Sprintf("invalid pattern %x", []byte(id)))
		}
		pattern = appendBase128(pattern, v)
	}
	return pattern
}

type KeyUsageConfig x509.KeyUsage

func (k *KeyUsageConfig) UnmarshalJSON(data []byte) error {
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	var result x509.KeyUsage
	for _, value := range values {
		switch value {
		case "DigitalSignature":
			result |= x509.KeyUsageDigitalSignature
		case "ContentCommitment":
			result |= x509.KeyUsageContentCommitment
		case "KeyEncipherment":
			result |= x509.KeyUsageKeyEncipherment
		case "DataEncipherment":
			result |= x509.KeyUsageDataEncipherment
		case "KeyAgreement":
			result |= x509.KeyUsageKeyAgreement
		case "CertSign":
			result |= x509.KeyUsageCertSign
		case "CRLSign":
			result |= x509.KeyUsageCRLSign
		case "EncipherOnly":
			result |= x509.KeyUsageEncipherOnly
		case "DecipherOnly":
			result |= x509.KeyUsageDecipherOnly
		default:
			return fmt.Errorf("unknown key usage %q", value)
		}
	}
	*k = KeyUsageConfig(result)
	return nil
}

type ExtKeyUsageConfig asn1.ObjectIdentifier

func (e *ExtKeyUsageConfig) UnmarshalText(text []byte) error {
	var oid asn1.ObjectIdentifier
	switch s := string(text); s {
	case "ServerAuth":
		oid = oidServerAuth
	default:
		for _, part := range strings.Split(s, ".") {
			v, err := strconv.Atoi(part)
			if err != nil || v < 0 {
				return fmt.Errorf("invalid extended key usage: %q", s)
			}
			oid = append(oid, v)
		}
		if len(oid) < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) {
			return fmt.Errorf("invalid extended key usage: %q", s)
		}
	}
	*e = ExtKeyUsageConfig(oid)
	return nil
}
