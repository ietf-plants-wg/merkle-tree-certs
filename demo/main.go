package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"golang.org/x/crypto/cryptobyte"
)

var (
	flagConfig = flag.String("config", "mtc.json", "the path to the config file to generate certificates from")
	flagOutDir = flag.String("out", "out", "the path to the output directory")
)

type certificateInfo struct {
	entryConfig       *EntryConfig
	certConfig        *CertificateConfig
	index, start, end int
	cosigners         []*CosignerConfig
	// The number of certificate for the given index.
	num int
}

func makeDirsAndWriteFile(name string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
		return err
	}
	return os.WriteFile(name, data, 0644)
}

func tlogIndex(n int, partial bool) string {
	if n < 0 {
		panic("negative tlog index")
	}
	var s string
	if partial {
		s = fmt.Sprintf("%03d.p", n%1000)
	} else {
		s = fmt.Sprintf("%03d", n%1000)
	}
	n /= 1000
	for n != 0 {
		s = filepath.Join(fmt.Sprintf("x%03d", n%1000), s)
		n /= 1000
	}
	return s
}

func tlogCheckpointKeyID(id TrustAnchorID) [4]byte {
	h := sha256.Sum256([]byte(tlogOrigin(id) + "\n\xffmtc-checkpoint/v1"))
	return *(*[4]byte)(h[:])
}

func do() error {
	// Load the config.
	configBytes, err := os.ReadFile(*flagConfig)
	if err != nil {
		return err
	}
	var config CAConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return err
	}

	// Entries in the issuance log.
	entries := [][]byte{MarshalNullEntry(config.Version)}
	// Certificates to be constructed.
	var certInfos []certificateInfo
	// Maps checkpoint sequence name to a list of certInfos indices that are
	// awaiting an end value once the next checkpoint in the sequence is
	// allocated.
	type checkpointWait struct {
		idx  int
		prev int
	}
	awaitingCheckpoint := map[string][]checkpointWait{}
	// Maps checkpoint sequence name to the latest checkpoint size.
	// Initially, all sequences are at zero, which matches the default map
	// lookup behavior.
	checkpointSeqs := map[string]int{}
	for entryConfigIdx := range config.Entries {
		entryConfig := &config.Entries[entryConfigIdx]
		repeat := 1
		if entryConfig.Repeat != 0 {
			repeat = entryConfig.Repeat
		}
		for range repeat {
			entry, err := MarshalTBSCertificateLogEntry(config.Version, config.LogID, entryConfig)
			if err != nil {
				return err
			}
			entries = append(entries, entry)
			entryIdx := len(entries) - 1

			// Schedule certificates.
			for certNum := range entryConfig.Certificates {
				certConfig := &entryConfig.Certificates[certNum]
				info := certificateInfo{index: entryIdx, entryConfig: entryConfig, certConfig: certConfig, num: certNum}
				if certConfig.SubtreeEnd != 0 {
					if len(certConfig.Checkpoint) != 0 {
						return fmt.Errorf("both Checkpoint and SubtreeEnd specified in a certificate")
					}
					info.start = certConfig.SubtreeStart
					info.end = certConfig.SubtreeEnd
				} else if c := certConfig.Checkpoint; len(c) != 0 {
					// Make a note to fill in the subtree when available.
					awaitingCheckpoint[c] = append(awaitingCheckpoint[c], checkpointWait{idx: len(certInfos), prev: checkpointSeqs[c]})
				} else {
					return fmt.Errorf("neither Checkpoint nor SubtreeEnd specified in a certificate")
				}
				for _, cosignerID := range certConfig.Cosigners {
					var cosigner *CosignerConfig
					for i := range config.Cosigners {
						if bytes.Equal(config.Cosigners[i].CosignerID, cosignerID) {
							cosigner = &config.Cosigners[i]
							break
						}
					}
					if cosigner == nil {
						return fmt.Errorf("cosigner %s not found", cosignerID)
					}
					info.cosigners = append(info.cosigners, cosigner)
				}
				certInfos = append(certInfos, info)
			}

			// Update checkpoint sequences.
			for _, seq := range entryConfig.Checkpoints {
				checkpointSeqs[seq] = len(entries)
				// Fill in any certificate infos that are still awaiting
				// a checkpoint.
				for _, wait := range awaitingCheckpoint[seq] {
					// We have the checkpoint interval. Find the two subtrees
					// and use the one that includes the certificate.
					start1, end1, start2, end2, err := SubtreesForInterval(wait.prev, len(entries))
					if err != nil {
						return err
					}
					if certInfos[wait.idx].index < end1 {
						certInfos[wait.idx].start = start1
						certInfos[wait.idx].end = end1
					} else {
						certInfos[wait.idx].start = start2
						certInfos[wait.idx].end = end2
					}
				}
				delete(awaitingCheckpoint, seq)
			}
		}
	}

	for seq := range awaitingCheckpoint {
		return fmt.Errorf("certificate required checkpoint sequence %q, but no checkpoint in sequence defined", seq)
	}

	issuanceLog := NewMerkleTree(entries)

	// Construct certificates.
	if err := os.MkdirAll(*flagOutDir, 0755); err != nil {
		log.Fatal(err)
	}
	for _, info := range certInfos {
		// TODO: A real CA would not generate fresh cosignatures for every
		// certificate. Rather it cosign subtrees as it checkpoints. This tool
		// is less opinionated about subtrees, so we would need to make a
		// cosignature cache to simulate this.
		cert, err := CreateCertificate(config.Version, issuanceLog, config.LogID, info.cosigners, info.entryConfig, info.certConfig, info.index, info.start, info.end)
		if err != nil {
			return err
		}

		subtree, err := issuanceLog.SubtreeHash(info.start, info.end)
		if err != nil {
			return err
		}

		certPath := filepath.Join(*flagOutDir, fmt.Sprintf("cert_%d_%d.pem", info.index, info.num))
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			return err
		}

		fmt.Printf("Wrote certificate for entry %d at %q.\n", info.index, certPath)
		fmt.Printf("  Subtree [%d, %d) with hash %s\n", info.start, info.end, base64.StdEncoding.EncodeToString(subtree[:]))
		for _, cosigner := range info.cosigners {
			fmt.Printf("  Cosigned by %s\n", cosigner.CosignerID)
		}
		fmt.Printf("\n")
	}

	// Write out the tree in tlog-tiles format.
	tileDir := filepath.Join(*flagOutDir, "tile")

	entryDir := filepath.Join(tileDir, "entries")
	for i := 0; 256*i < len(entries); i++ {
		bundle := cryptobyte.NewBuilder(nil)
		for j := 256 * i; j < 256*(i+1) && j < len(entries); j++ {
			bundle.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(entries[j]) })
		}
		var path string
		if 256*(i+1) <= len(entries) {
			path = filepath.Join(entryDir, tlogIndex(i, false))
		} else {
			path = filepath.Join(entryDir, tlogIndex(i, true), strconv.Itoa(len(entries)-256*i))
		}
		data, err := bundle.Bytes()
		if err != nil {
			return err
		}
		if err := makeDirsAndWriteFile(path, data); err != nil {
			return err
		}
	}

	for l := 0; l < len(issuanceLog.levels); l += 8 {
		level := issuanceLog.levels[l]
		for i := 0; 256*i < len(level); i++ {
			var tile []byte
			for j := 256 * i; j < 256*(i+1) && j < len(level); j++ {
				tile = append(tile, level[j][:]...)
			}
			var path string
			if 256*(i+1) <= len(level) {
				path = filepath.Join(tileDir, strconv.Itoa(l/8), tlogIndex(i, false))
			} else {
				path = filepath.Join(tileDir, strconv.Itoa(l/8), tlogIndex(i, true), strconv.Itoa(len(level)-256*i))
			}
			if err := makeDirsAndWriteFile(path, tile); err != nil {
				return err
			}
		}
	}

	checkpointHash, err := issuanceLog.SubtreeHash(0, len(entries))
	if err != nil {
		panic(err)
	}
	var signedNote bytes.Buffer
	fmt.Fprintf(&signedNote, "%s\n", tlogOrigin(config.LogID))
	fmt.Fprintf(&signedNote, "%d\n", len(entries))
	fmt.Fprintf(&signedNote, "%s\n\n", base64.StdEncoding.EncodeToString(checkpointHash[:]))
	for i := range config.Cosigners {
		cosigner := &config.Cosigners[i]
		cosig, err := Cosign(config.Version, cosigner, config.LogID, 0, len(entries), &checkpointHash)
		if err != nil {
			return err
		}
		keyID := tlogCheckpointKeyID(cosigner.CosignerID)
		fmt.Fprintf(&signedNote, "\u2014 %s %s\n", tlogOrigin(cosigner.CosignerID), base64.StdEncoding.EncodeToString(slices.Concat(keyID[:], cosig)))
	}
	if err := os.WriteFile(filepath.Join(*flagOutDir, "checkpoint"), signedNote.Bytes(), 0644); err != nil {
		return err
	}

	return nil
}

func main() {
	flag.Parse()
	if err := do(); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating certificates: %s\n", err)
		os.Exit(1)
	}
}
