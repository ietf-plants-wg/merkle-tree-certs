package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	logEntryTypeX509    = 0
	logEntryTypePrecert = 1

	fullTileSize = 256

	tbsCertEntry = 1
)

var (
	flagURL            = flag.String("url", "", "the URL of the log to sample")
	flagSamples        = flag.Int("samples", 5, "number of samples to run")
	flagFilterKeyIDs   = flag.Bool("filter-key-id", false, "filter out SKID and AKID extensions")
	flagFilterAIA      = flag.Bool("filter-aia", false, "filter out AIA extension")
	flagPQEmbeddedSCTs = flag.Bool("pq-embedded-scts", false, "simulate embedded SCTs getting upgraded to post-quantum")
	flagPQAlg          = flag.String("pq-alg", "ML-DSA-44", "the PQ algorithm to simulate")
	flagUserAgent      = flag.String("user-agent", "", "the User-Agent value to send to the log")

	// Put together some placeholder value based on https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-06.html#name-log-ids
	placeholderIssuer = []byte{0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x00, 0x00, 0x0d, 0x04, 0xd6, 0x79, 0x09, 0x01}
)

type pqAlgorithm struct {
	publicKeySize int
	signatureSize int
}

func getPQAlgorithm(alg string) (pqAlgorithm, bool) {
	switch alg {
	case "ML-DSA-44":
		return pqAlgorithm{publicKeySize: 1312, signatureSize: 2420}, true
	case "ML-DSA-65":
		return pqAlgorithm{publicKeySize: 1952, signatureSize: 3309}, true
	case "ML-DSA-87":
		return pqAlgorithm{publicKeySize: 2592, signatureSize: 4627}, true
	}
	return pqAlgorithm{}, false
}

// Extracts leaf certificates from a data tile, as defined in https://c2sp.org/static-ct-api
func parseDataTile(tile []byte, n int) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, n)
	in := cryptobyte.String(tile)
	for i := range n {
		var logEntryType uint16
		if !in.Skip(8) ||
			!in.ReadUint16(&logEntryType) {
			return nil, errors.New("could not parse tile leaf")
		}

		var skip, cert cryptobyte.String
		switch logEntryType {
		case logEntryTypeX509:
			if !in.ReadUint24LengthPrefixed(&cert) ||
				!in.ReadUint16LengthPrefixed(&skip) /* ext */ ||
				!in.ReadUint16LengthPrefixed(&skip) /* cert chain */ {
				return nil, errors.New("could not parse tile leaf")
			}
		case logEntryTypePrecert:
			if !in.Skip(32) /* hash */ ||
				!in.ReadUint24LengthPrefixed(&skip) /* tbs */ ||
				!in.ReadUint16LengthPrefixed(&skip) /* ext */ ||
				!in.ReadUint24LengthPrefixed(&cert) ||
				!in.ReadUint16LengthPrefixed(&skip) /* cert chain */ {
				return nil, errors.New("could not parse tile leaf")
			}
		default:
			return nil, errors.New("unknown log entry type")
		}

		c, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, err
		}
		certs[i] = c
	}
	if !in.Empty() {
		return nil, errors.New("excess data in data tile")
	}
	return certs, nil
}

func addX509Time(bb *cryptobyte.Builder, t time.Time) {
	t = t.UTC()
	if y := t.Year(); 1950 <= y && y <= 2049 {
		bb.AddASN1UTCTime(t)
	} else {
		bb.AddASN1GeneralizedTime(t)
	}
}

var (
	oidSubjectKeyId               = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyId             = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidAuthorityInformationAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidSCTExtension               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// Encodes a representative TBSCertificateLogEntry from an X.509 Certificate, as defined in draft-davidben-tls-merkle-tree-certs-06.
func tbsCertLogEntryFromCert(cert *x509.Certificate) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(tbsCertEntry)
	b.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
		tbs.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(vers *cryptobyte.Builder) {
			vers.AddASN1Int64(2)
		})
		tbs.AddBytes(placeholderIssuer)
		tbs.AddASN1(cbasn1.SEQUENCE, func(val *cryptobyte.Builder) {
			addX509Time(val, cert.NotBefore)
			addX509Time(val, cert.NotAfter)
		})
		tbs.AddBytes(cert.RawSubject)
		// Parse out the algorithm.
		spki := cryptobyte.String(cert.RawSubjectPublicKeyInfo)
		var spkiContents, spkiAlg cryptobyte.String
		if !spki.ReadASN1(&spkiContents, cbasn1.SEQUENCE) ||
			!spkiContents.ReadASN1Element(&spkiAlg, cbasn1.SEQUENCE) {
			panic("could not parse SPKI")
		}
		tbs.AddBytes(spkiAlg)
		hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		tbs.AddASN1OctetString(hash[:])
		tbs.AddASN1(cbasn1.Tag(3).Constructed().ContextSpecific(), func(exts *cryptobyte.Builder) {
			certExts := slices.DeleteFunc(slices.Clone(cert.Extensions), func(ext pkix.Extension) bool {
				// Today's CT logs often log certificates with embedded SCTs due to an awkward parts
				// of how CT was designed. These would not exist at all in MTCs.
				if ext.Id.Equal(oidSCTExtension) {
					return true
				}
				// SKIDs and AKIDs only exist to aid path-building when one CA name corresponds to
				// multiple keys. MTC fixes this at the source and requires a distinct CA name, so
				// PKIs can reasonably say to omit them.
				if *flagFilterKeyIDs && (ext.Id.Equal(oidSubjectKeyId) || ext.Id.Equal(oidAuthorityKeyId)) {
					return true
				}
				// AIA is only needed to deal with a host of issues around path-building, which we
				// can fix at the source with negotiation.
				if *flagFilterAIA && ext.Id.Equal(oidAuthorityInformationAccess) {
					return true
				}
				return false
			})
			der, err := asn1.Marshal(certExts)
			if err != nil {
				panic(err)
			}
			exts.AddBytes(der)
		})
	})
	return b.BytesOrPanic()
}

type embeddedSCTInfo struct {
	numSCTs int
	totSig  int
}

func parseEmbeddedSCTs(cert *x509.Certificate) (embeddedSCTInfo, error) {
	var info embeddedSCTInfo
	var ext *pkix.Extension
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(oidSCTExtension) {
			ext = &cert.Extensions[i]
			break
		}
	}
	if ext == nil {
		return info, nil
	}

	value := cryptobyte.String(ext.Value)
	var sctList, scts cryptobyte.String
	if !value.ReadASN1(&sctList, cbasn1.OCTET_STRING) || !value.Empty() ||
		!sctList.ReadUint16LengthPrefixed(&scts) || !sctList.Empty() ||
		scts.Empty() {
		return embeddedSCTInfo{}, fmt.Errorf("error parsing SCT extension")
	}
	for !scts.Empty() {
		var sct, ctExts, sig cryptobyte.String
		if !scts.ReadUint16LengthPrefixed(&sct) ||
			!sct.Skip(1+32+8) || // version, id, timestamp
			!sct.ReadUint16LengthPrefixed(&ctExts) ||
			!sct.Skip(2) || // sigalg
			!sct.ReadUint16LengthPrefixed(&sig) ||
			!sct.Empty() {
			return embeddedSCTInfo{}, fmt.Errorf("error parsing SCT extension")
		}
		info.numSCTs++
		info.totSig += len(sig)
	}
	return info, nil
}

func fetch(url *url.URL) (*http.Response, error) {
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, err
	}
	if *flagUserAgent != "" {
		req.Header.Add("User-Agent", *flagUserAgent)
	}
	return http.DefaultClient.Do(req)
}

func fetchTreeSize(baseURL *url.URL) (int, error) {
	resp, err := fetch(baseURL.JoinPath("checkpoint"))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("got non-200 status %d from checkpoint", resp.StatusCode)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("bad checkpoint")
	}
	return strconv.Atoi(lines[1])
}

func encodeIndex(idx int) string {
	ret := fmt.Sprintf("%03d", idx%1000)
	idx /= 1000
	for idx != 0 {
		ret = fmt.Sprintf("x%03d/", idx%1000) + ret
		idx /= 1000
	}
	return ret
}

func fetchDataTile(baseURL *url.URL, idx, size int) ([]byte, error) {
	baseURL = baseURL.JoinPath("tile", "data")
	if size == fullTileSize {
		baseURL = baseURL.JoinPath(encodeIndex(idx))
	} else {
		baseURL = baseURL.JoinPath(encodeIndex(idx)+".p", strconv.Itoa(size))
	}
	resp, err := fetch(baseURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("got non-200 status %d from data tile fetch", resp.StatusCode)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func gzipSize(in []byte) int {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(in); err != nil {
		panic(err)
	}
	if err := w.Flush(); err != nil {
		panic(err)
	}
	return b.Len()
}

func percent(a, b int) float64 {
	return 100.0 * float64(a) / float64(b)
}

type tileStats struct {
	name         string
	tot, gzipTot int
}

func printAvg(s tileStats) {
	fmt.Printf("Average %s tile: %.2f bytes (%.2f bytes gzipped)\n", s.name, float64(s.tot)/float64(*flagSamples), float64(s.gzipTot)/float64(*flagSamples))
}

func compareStats(s1, s2 tileStats) {
	fmt.Printf("%s / %s: %.2f%% uncompressed, %.2f%% gzipped\n", s1.name, s2.name, percent(s1.tot, s2.tot), percent(s1.gzipTot, s2.gzipTot))
}

func ifElse[T any](b bool, ifTrue, ifFalse T) T {
	if b {
		return ifTrue
	} else {
		return ifFalse
	}
}

func do() error {
	if len(*flagURL) == 0 {
		return errors.New("no log supplied, see https://googlechrome.github.io/CertificateTransparency/log_lists.html for available logs (must be tiled)")
	}
	baseURL, err := url.Parse(*flagURL)
	if err != nil {
		return err
	}
	if !baseURL.IsAbs() {
		return errors.New("not a valid URL")
	}
	pqAlg, ok := getPQAlgorithm(*flagPQAlg)
	if !ok {
		return fmt.Errorf("unknown post-quantum algorithm: %s", *flagPQAlg)
	}

	fmt.Printf("Sampling %d tile%s from log %s\n", *flagSamples, ifElse(*flagSamples == 1, "", "s"), *flagURL)

	treeSize, err := fetchTreeSize(baseURL)
	if err != nil {
		return err
	}
	fmt.Printf("Tree size: %d\n", treeSize)

	ctStats := tileStats{name: "CT"}
	mtcStats := tileStats{name: "MTC"}
	pqCTStats := tileStats{name: "PQ CT"}

	for range *flagSamples {
		numFullTiles := treeSize / fullTileSize

		sample := rand.IntN(numFullTiles)
		tileSize := fullTileSize
		fmt.Printf("Sampling tile %d\n", sample)

		tile, err := fetchDataTile(baseURL, sample, tileSize)
		if err != nil {
			return err
		}
		// For a fair comparison, redo the gzip rather than reuse the original
		// log's gzip, so that CT and MTC tiles have the same gzip settings.
		ctGzipSize := gzipSize(tile)

		certs, err := parseDataTile(tile, tileSize)
		if err != nil {
			return err
		}

		pqIncrease := 0
		b := cryptobyte.NewBuilder(nil)
		for _, cert := range certs {
			scts, err := parseEmbeddedSCTs(cert)
			if err != nil {
				return err
			}

			// As a very, very rough estimate of the status quo with PQ,
			// simulate replacing the leaf SPKI, leaf signature, and embedded
			// SCT signatures with the chosen PQ algorithm.
			pqIncrease += pqAlg.publicKeySize - len(cert.RawSubjectPublicKeyInfo)
			pqIncrease += pqAlg.signatureSize - len(cert.Signature)
			if *flagPQEmbeddedSCTs {
				pqIncrease += scts.numSCTs*pqAlg.signatureSize - scts.totSig
			}

			// Construct the MTC tiles.
			entry := tbsCertLogEntryFromCert(cert)
			b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
				child.AddBytes(entry)
			})
		}
		mtcTile := b.BytesOrPanic()
		mtcGzipSize := gzipSize(mtcTile)

		ctStats.tot += len(tile)
		ctStats.gzipTot += ctGzipSize
		// Assume that keys and signatures are incompressible, so just add it to
		// the gzip sizes.
		pqCTStats.tot += len(tile) + pqIncrease
		pqCTStats.gzipTot += ctGzipSize + pqIncrease
		mtcStats.tot += len(mtcTile)
		mtcStats.gzipTot += mtcGzipSize
	}

	fmt.Printf("\n")
	printAvg(ctStats)
	printAvg(pqCTStats)
	fmt.Printf("    Simulated by replacing public keys and signatures with %s\n", *flagPQAlg)
	fmt.Printf("    Embedded SCT signatures %s replaced\n", ifElse(*flagPQEmbeddedSCTs, "also", "not"))
	printAvg(mtcStats)
	fmt.Printf("    Simulated by converting CT tiles to MTC tiles\n")
	fmt.Printf("    AIA extensions %sremoved (AIA is unnecessary without path-building)\n", ifElse(*flagFilterAIA, "", "not "))
	fmt.Printf("    SKID/AKID extensions %sremoved (SKID/AKID are unnecessary without path-building)\n", ifElse(*flagFilterKeyIDs, "", "not "))
	fmt.Printf("(PQ MTC and MTC tiles have the same size.)\n")
	fmt.Printf("\n")

	compareStats(pqCTStats, ctStats)
	compareStats(mtcStats, ctStats)
	compareStats(mtcStats, pqCTStats)
	return nil
}

func main() {
	flag.Parse()
	if err := do(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
		os.Exit(1)
	}
}
