package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"fmt"
	"io"
	"slices"

	"filippo.io/mldsa"
	"golang.org/x/crypto/cryptobyte"
)

func addTrustAnchorID(b *cryptobyte.Builder, id TrustAnchorID) {
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(id)
	})
}

func tlogOrigin(id TrustAnchorID) string {
	return fmt.Sprintf("oid/1.3.6.1.4.1.%s", id)
}

// When ML-DSA is added to the Go standard library, these wrappers can be
// removed.

var (
	mldsa44PKCS8Prefix = []byte{0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11, 0x04, 0x22, 0x80, 0x20}
	mldsa65PKCS8Prefix = []byte{0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12, 0x04, 0x22, 0x80, 0x20}
	mldsa87PKCS8Prefix = []byte{0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13, 0x04, 0x22, 0x80, 0x20}

	mldsa44SPKIPrefix = []byte{0x30, 0x82, 0x05, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11, 0x03, 0x82, 0x05, 0x21, 0x00}
	mldsa65SPKIPrefix = []byte{0x30, 0x82, 0x05, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12, 0x03, 0x82, 0x05, 0x21, 0x00}
	mldsa87SPKIPrefix = []byte{0x30, 0x82, 0x05, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13, 0x03, 0x82, 0x05, 0x21, 0x00}
)

func parsePKCS8PrivateKey(der []byte) (key any, err error) {
	if seed, ok := bytes.CutPrefix(der, mldsa44PKCS8Prefix); ok && len(seed) == mldsa.PrivateKeySize {
		return mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	}
	if seed, ok := bytes.CutPrefix(der, mldsa65PKCS8Prefix); ok && len(seed) == mldsa.PrivateKeySize {
		return mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	}
	if seed, ok := bytes.CutPrefix(der, mldsa87PKCS8Prefix); ok && len(seed) == mldsa.PrivateKeySize {
		return mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
	}
	return x509.ParsePKCS8PrivateKey(der)
}

func marshalPKIXPublicKey(pub any) ([]byte, error) {
	if ml, ok := pub.(*mldsa.PublicKey); ok {
		switch ml.Parameters() {
		case mldsa.MLDSA44():
			return append(slices.Clip(mldsa44SPKIPrefix), ml.Bytes()...), nil
		case mldsa.MLDSA65():
			return append(slices.Clip(mldsa65SPKIPrefix), ml.Bytes()...), nil
		case mldsa.MLDSA87():
			return append(slices.Clip(mldsa87SPKIPrefix), ml.Bytes()...), nil
		}
		panic("unknown ML-DSA parameters")
	}
	return x509.MarshalPKIXPublicKey(pub)
}

type Cosigner struct {
	Version            DraftVersion
	ID                 TrustAnchorID
	KeyID              [4]byte
	SignatureAlgorithm SignatureAlgorithm
	Signer             crypto.Signer
	SignerOpts         crypto.SignerOpts
}

func NewCosignerFromConfig(version DraftVersion, config *CosignerConfig) (*Cosigner, error) {
	priv, err := parsePKCS8PrivateKey(config.PrivateKey)
	if err != nil {
		return nil, err
	}

	var signer crypto.Signer
	var opts crypto.SignerOpts
	switch config.SignatureAlgorithm {
	case SignatureAlgorithmP256WithSHA256:
		ec, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an EC key")
		}
		if ec.Curve != elliptic.P256() {
			return nil, fmt.Errorf("not a P-256 key")
		}
		signer = ec
		opts = crypto.SHA256
	case SignatureAlgorithmP384WithSHA384:
		ec, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an EC key")
		}
		if ec.Curve != elliptic.P384() {
			return nil, fmt.Errorf("not a P-384 key")
		}
		signer = ec
		opts = crypto.SHA384
	case SignatureAlgorithmEd25519:
		// Unlike the others, ed25519.PrivateKey is not returned as a pointer.
		ed, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an Ed25519 key")
		}
		signer = ed
		opts = crypto.Hash(0)
	case SignatureAlgorithmMLDSA44, SignatureAlgorithmMLDSA65, SignatureAlgorithmMLDSA87:
		var params *mldsa.Parameters
		switch config.SignatureAlgorithm {
		case SignatureAlgorithmMLDSA44:
			params = mldsa.MLDSA44()
		case SignatureAlgorithmMLDSA65:
			params = mldsa.MLDSA65()
		case SignatureAlgorithmMLDSA87:
			params = mldsa.MLDSA87()
		}
		ml, ok := priv.(*mldsa.PrivateKey)
		if !ok || ml.PublicKey().Parameters() != params {
			return nil, fmt.Errorf("not a %s key", params)
		}
		signer = ml
		opts = crypto.Hash(0)
	default:
		return nil, fmt.Errorf("unexpected signature algorithm %s", config.SignatureAlgorithm)
	}

	// Compute a tlog key ID.
	h := sha256.New()
	io.WriteString(h, tlogOrigin(config.CosignerID))
	if version >= VersionPlants04 && config.SignatureAlgorithm == SignatureAlgorithmMLDSA44 {
		// plants-04 uses a signature scheme compatible with tlog-cosignature's
		// ML-DSA-44 scheme.
		io.WriteString(h, "\n\x06")
		h.Write(signer.Public().(*mldsa.PublicKey).Bytes())
	} else {
		// Use some placeholder value until a signature scheme is defined.
		io.WriteString(h, "\n\xffmtc-checkpoint/v1")
	}
	keyID := *(*[4]byte)(h.Sum(nil)[:4])

	return &Cosigner{
		Version:            version,
		ID:                 config.CosignerID,
		KeyID:              keyID,
		SignatureAlgorithm: config.SignatureAlgorithm,
		Signer:             signer,
		SignerOpts:         opts,
	}, nil
}

func (c *Cosigner) Sign(logID TrustAnchorID, start, end int, hash *HashValue) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	if c.Version >= VersionPlants04 {
		b.AddBytes([]byte("subtree/v1\n\x00"))
		b.AddUint8LengthPrefixed(func(cosignerName *cryptobyte.Builder) {
			cosignerName.AddBytes([]byte(tlogOrigin(c.ID)))
		})
		b.AddUint64(0) // timestamp
		b.AddUint8LengthPrefixed(func(logOrigin *cryptobyte.Builder) {
			logOrigin.AddBytes([]byte(tlogOrigin(logID)))
		})
	} else {
		b.AddBytes([]byte("mtc-subtree/v1\n\x00"))
		addTrustAnchorID(b, c.ID)
		addTrustAnchorID(b, logID)
	}
	if !IsValidSubtree(start, end) {
		return nil, fmt.Errorf("invalid subtree")
	}
	b.AddUint64(uint64(start))
	b.AddUint64(uint64(end))
	b.AddBytes((*hash)[:])
	inp, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	return crypto.SignMessage(c.Signer, rand.Reader, inp, c.SignerOpts)
}
