package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

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

// cosignedMessage returns the message a cosigner signs. timestamp is zero for
// a subtree cosignature, and the signing time for a checkpoint cosignature
// (see https://c2sp.org/tlog-cosignature@v1.1.0), which covers [0, end).
func cosignedMessage(version DraftVersion, cosignerID, logID TrustAnchorID, timestamp, start, end uint64, hash *HashValue) ([]byte, error) {
	if timestamp != 0 && start != 0 {
		return nil, fmt.Errorf("only a checkpoint cosignature, with start zero, has a timestamp")
	}
	b := cryptobyte.NewBuilder(nil)
	if version >= VersionPlants04 {
		b.AddBytes([]byte("subtree/v1\n\x00"))
		b.AddUint8LengthPrefixed(func(cosignerName *cryptobyte.Builder) {
			cosignerName.AddBytes([]byte(tlogOrigin(cosignerID)))
		})
		b.AddUint64(timestamp)
		b.AddUint8LengthPrefixed(func(logOrigin *cryptobyte.Builder) {
			logOrigin.AddBytes([]byte(tlogOrigin(logID)))
		})
	} else {
		if timestamp != 0 {
			return nil, fmt.Errorf("timestamped cosignatures require plants-04 or later")
		}
		b.AddBytes([]byte("mtc-subtree/v1\n\x00"))
		addTrustAnchorID(b, cosignerID)
		addTrustAnchorID(b, logID)
	}
	if !IsValidSubtree(start, end) {
		return nil, fmt.Errorf("invalid subtree")
	}
	b.AddUint64(start)
	b.AddUint64(end)
	b.AddBytes((*hash)[:])
	return b.Bytes()
}

func mldsaParamsFromAlg(alg SignatureAlgorithm) mldsa.Parameters {
	switch alg {
	case SignatureAlgorithmMLDSA44:
		return mldsa.MLDSA44()
	case SignatureAlgorithmMLDSA65:
		return mldsa.MLDSA65()
	case SignatureAlgorithmMLDSA87:
		return mldsa.MLDSA87()
	}
	panic("unknown signature algorithm")
}

func ecdsaParamsFromAlg(alg SignatureAlgorithm) (elliptic.Curve, crypto.Hash) {
	switch alg {
	case SignatureAlgorithmP256WithSHA256:
		return elliptic.P256(), crypto.SHA256
	case SignatureAlgorithmP384WithSHA384:
		return elliptic.P384(), crypto.SHA384
	}
	panic("unknown signature algorithm")
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
	priv, err := x509.ParsePKCS8PrivateKey(config.PrivateKey)
	if err != nil {
		return nil, err
	}

	var signer crypto.Signer
	var opts crypto.SignerOpts
	switch config.SignatureAlgorithm {
	case SignatureAlgorithmP256WithSHA256, SignatureAlgorithmP384WithSHA384:
		curve, hash := ecdsaParamsFromAlg(config.SignatureAlgorithm)
		ec, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an EC key")
		}
		if ec.Curve != curve {
			return nil, fmt.Errorf("not a %s key", curve.Params().Name)
		}
		signer = ec
		opts = hash
	case SignatureAlgorithmEd25519:
		// Unlike the others, ed25519.PrivateKey is not returned as a pointer.
		ed, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an Ed25519 key")
		}
		signer = ed
		opts = crypto.Hash(0)
	case SignatureAlgorithmMLDSA44, SignatureAlgorithmMLDSA65, SignatureAlgorithmMLDSA87:
		params := mldsaParamsFromAlg(config.SignatureAlgorithm)
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

// Sign returns a subtree cosignature: the signature alone, over a message with
// a zero timestamp.
func (c *Cosigner) Sign(logID TrustAnchorID, start, end uint64, hash *HashValue) ([]byte, error) {
	return c.sign(logID, 0, start, end, hash)
}

// SignCheckpoint returns a checkpoint cosignature for the log's first size
// entries, as https://c2sp.org/tlog-cosignature@v1.1.0 defines it: the
// timestamp as an eight-byte, big-endian integer, followed by the signature
// over a message carrying the same timestamp. Before plants-04 the message has
// no timestamp, so the signature alone is returned.
func (c *Cosigner) SignCheckpoint(logID TrustAnchorID, size, timestamp uint64, hash *HashValue) ([]byte, error) {
	if c.Version < VersionPlants04 {
		return c.sign(logID, 0, 0, size, hash)
	}
	sig, err := c.sign(logID, timestamp, 0, size, hash)
	if err != nil {
		return nil, err
	}
	return append(binary.BigEndian.AppendUint64(nil, timestamp), sig...), nil
}

func (c *Cosigner) sign(logID TrustAnchorID, timestamp, start, end uint64, hash *HashValue) ([]byte, error) {
	inp, err := cosignedMessage(c.Version, c.ID, logID, timestamp, start, end, hash)
	if err != nil {
		return nil, err
	}

	return crypto.SignMessage(c.Signer, rand.Reader, inp, c.SignerOpts)
}

type CosignerPublic struct {
	Version            DraftVersion
	ID                 TrustAnchorID
	SignatureAlgorithm SignatureAlgorithm
	PublicKey          crypto.PublicKey
}

func NewCosignerPublic(vers DraftVersion, id TrustAnchorID, sigAlg SignatureAlgorithm, pubkey crypto.PublicKey) (*CosignerPublic, error) {
	// See x509.ParsePKIXPublicKey's documentation for the key types.
	switch sigAlg {
	case SignatureAlgorithmEd25519:
		if _, ok := pubkey.(ed25519.PublicKey); !ok {
			return nil, errors.New("not an Ed25519 key")
		}
	case SignatureAlgorithmMLDSA44, SignatureAlgorithmMLDSA65, SignatureAlgorithmMLDSA87:
		params := mldsaParamsFromAlg(sigAlg)
		ml, ok := pubkey.(*mldsa.PublicKey)
		if !ok || ml.Parameters() != params {
			return nil, fmt.Errorf("not a %s key", params)
		}
	case SignatureAlgorithmP256WithSHA256, SignatureAlgorithmP384WithSHA384:
		curve, _ := ecdsaParamsFromAlg(sigAlg)
		ec, ok := pubkey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an EC key")
		}
		if ec.Curve != curve {
			return nil, fmt.Errorf("not a %s key", curve.Params().Name)
		}
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", sigAlg)
	}

	return &CosignerPublic{Version: vers, ID: id, SignatureAlgorithm: sigAlg, PublicKey: pubkey}, nil
}

func (c *CosignerPublic) Verify(logID TrustAnchorID, start, end uint64, hash *HashValue, sig []byte) error {
	inp, err := cosignedMessage(c.Version, c.ID, logID, 0, start, end, hash)
	if err != nil {
		return err
	}

	// See x509.ParsePKIXPublicKey's documentation for the key types. We assume
	// the checks in NewCosignerPublic have already passed.
	switch c.SignatureAlgorithm {
	case SignatureAlgorithmEd25519:
		if !ed25519.Verify(c.PublicKey.(ed25519.PublicKey), inp, sig) {
			return errors.New("invalid Ed25519 signature")
		}
		return nil
	case SignatureAlgorithmMLDSA44, SignatureAlgorithmMLDSA65, SignatureAlgorithmMLDSA87:
		return mldsa.Verify(c.PublicKey.(*mldsa.PublicKey), inp, sig, nil)
	case SignatureAlgorithmP256WithSHA256, SignatureAlgorithmP384WithSHA384:
		_, hash := ecdsaParamsFromAlg(c.SignatureAlgorithm)
		h := hash.New()
		h.Write(inp)
		if !ecdsa.VerifyASN1(c.PublicKey.(*ecdsa.PublicKey), h.Sum(nil), sig) {
			return errors.New("invalid ECDSA signature")
		}
		return nil
	default:
		panic(fmt.Sprintf("unexpected signature algorithm: %s", c.SignatureAlgorithm))
	}
}
