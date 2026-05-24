package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"fmt"

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

func Cosign(version DraftVersion, c *CosignerConfig, logID TrustAnchorID, start, end int, hash *HashValue) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	if version >= VersionPlants04 {
		b.AddBytes([]byte("subtree/v1\n\x00"))
		b.AddUint8LengthPrefixed(func(cosignerName *cryptobyte.Builder) {
			cosignerName.AddBytes([]byte(tlogOrigin(c.CosignerID)))
		})
		b.AddUint64(0) // timestamp
		b.AddUint8LengthPrefixed(func(logOrigin *cryptobyte.Builder) {
			logOrigin.AddBytes([]byte(tlogOrigin(logID)))
		})
	} else {
		b.AddBytes([]byte("mtc-subtree/v1\n\x00"))
		addTrustAnchorID(b, c.CosignerID)
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

	priv, err := x509.ParsePKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return nil, err
	}

	var signer crypto.Signer
	var opts crypto.SignerOpts
	switch c.SignatureAlgorithm {
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
	default:
		return nil, fmt.Errorf("unexpected signature algorithm %s", c.SignatureAlgorithm)
	}

	return crypto.SignMessage(signer, rand.Reader, inp, opts)
}
