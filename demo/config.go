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
	}
	panic(fmt.Sprintf("unknown version %d", v))
}

func (v *DraftVersion) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	var ok bool
	*v, ok = DraftVersionFromString(s)
	if !ok {
		return fmt.Errorf("unknown version %q", s)
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

	default:
		return 0, false
	}
}

type SignatureAlgorithm int

const (
	SignatureAlgorithmP256WithSHA256 SignatureAlgorithm = iota
	SignatureAlgorithmP384WithSHA384
	SignatureAlgorithmEd25519
	// TODO: Add ML-DSA once Go's standard library supports it.
)

func SignatureAlgorithmFromString(s string) (SignatureAlgorithm, bool) {
	switch s {
	case "ecdsa_p256_sha256":
		return SignatureAlgorithmP256WithSHA256, true
	case "ecdsa_p384_sha384":
		return SignatureAlgorithmP384WithSHA384, true
	case "ed25519":
		return SignatureAlgorithmEd25519, true
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
	default:
		panic(fmt.Sprintf("unexpected SignatureAlgorithm: %#v", s))
	}
}

func (s *SignatureAlgorithm) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	var ok bool
	*s, ok = SignatureAlgorithmFromString(v)
	if !ok {
		return fmt.Errorf("invalid signature algorithm: %q", v)
	}
	return nil
}

type CAConfig struct {
	Version   DraftVersion
	LogID     TrustAnchorID
	Cosigners []CosignerConfig
	Entries   []EntryConfig
}

type CosignerConfig struct {
	CosignerID         TrustAnchorID
	SignatureAlgorithm SignatureAlgorithm
	PrivateKey         []byte
}

type EntryConfig struct {
	// A number of times to repeat this entry.
	Repeat              int
	Subject             SubjectConfig
	PublicKey           []byte
	NotBefore, NotAfter time.Time
	DNSNames            []string
	KeyUsage            KeyUsageConfig
	ExtKeyUsage         []ExtKeyUsageConfig
	IsCA                *bool
	MaxPathLen          *int64
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
	SubtreeStart, SubtreeEnd int
	Checkpoint               string
	// Must refer to a cosigner defined in the CAConfig.
	Cosigners []TrustAnchorID
	// BitFlipProof, if true, flips a bit in the inclusion proof.
	BitFlipProof bool
	// UnusedBit, if true, encodes the last bit in the signatureValue, which
	// must be zero, as unused. This makes the signatureValue a non-whole
	// number of bytes.
	UnusedBit bool
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
	var s strings.Builder
	for len(t) != 0 {
		v, rest, ok := parseBase128(t)
		if !ok {
			return fmt.Sprintf("<invalid: %x>", []byte(t))
		}
		if s.Len() != 0 {
			s.WriteByte('.')
		}
		fmt.Fprintf(&s, "%d", v)
		t = rest
	}
	return s.String()
}

func (t *TrustAnchorID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	var ok bool
	*t, ok = TrustAnchorIDFromString(s)
	if !ok {
		return fmt.Errorf("invalid trust anchor ID: %q", s)
	}
	return nil
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

func (e *ExtKeyUsageConfig) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	var oid asn1.ObjectIdentifier
	switch value {
	case "ServerAuth":
		oid = oidServerAuth
	default:
		for _, part := range strings.Split(value, ".") {
			v, err := strconv.Atoi(part)
			if err != nil || v < 0 {
				return fmt.Errorf("invalid extended key usage: %q", value)
			}
			oid = append(oid, v)
		}
		if len(oid) < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) {
			return fmt.Errorf("invalid extended key usage: %q", value)
		}
	}
	*e = ExtKeyUsageConfig(oid)
	return nil
}
