package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
)

// These tests reproduce the accumulated test vectors from the "Subtree Test
// Vectors" appendix. For trees of sizes up to 130, they fold the output of each
// subtree algorithm over every valid input into a single rolling SHA-256, which
// is compared against the value published in the draft.

const subtreeVectorMax = 130

// subtreeVectorTree builds the tree D used by the test vectors, with leaf values
// d[0] = 0x00, d[1] = 0x01, and so on.
func subtreeVectorTree() *MerkleTree {
	entries := make([][]byte, subtreeVectorMax)
	for i := range entries {
		entries[i] = []byte{byte(i)}
	}
	return NewMerkleTree(entries)
}

// writeProofLine writes prefix followed by, for each hash in the concatenated
// proof, a space and the hash's hexadecimal encoding, then a newline. An empty
// proof contributes no hashes and so leaves no trailing space.
func writeProofLine(w io.Writer, prefix string, proof []byte) {
	io.WriteString(w, prefix)
	for off := 0; off < len(proof); off += HashSize {
		fmt.Fprintf(w, " %x", proof[off:off+HashSize])
	}
	io.WriteString(w, "\n")
}

func TestSubtreeHashVectors(t *testing.T) {
	tree := subtreeVectorTree()
	h := sha256.New()
	for end := 1; end <= subtreeVectorMax; end++ {
		for start := 0; start < end; start++ {
			if !IsValidSubtree(start, end) {
				continue
			}
			subtreeHash, err := tree.SubtreeHash(start, end)
			if err != nil {
				t.Fatalf("SubtreeHash(%d, %d): %v", start, end, err)
			}
			fmt.Fprintf(h, "[%d, %d) %x\n", start, end, subtreeHash[:])
		}
	}
	const want = "94a95384a8c69acea9b50d035a58285b3a777cb7a724005faa5e1f1e1190007f"
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		t.Errorf("subtree hash vector = %s, want %s", got, want)
	}
}

func TestSubtreeInclusionProofVectors(t *testing.T) {
	tree := subtreeVectorTree()
	h := sha256.New()
	for end := 1; end <= subtreeVectorMax; end++ {
		for start := 0; start < end; start++ {
			if !IsValidSubtree(start, end) {
				continue
			}
			for index := start; index < end; index++ {
				proof, err := tree.SubtreeInclusionProof(index, start, end)
				if err != nil {
					t.Fatalf("SubtreeInclusionProof(%d, %d, %d): %v", index, start, end, err)
				}
				writeProofLine(h, fmt.Sprintf("%d [%d, %d)", index, start, end), proof)
			}
		}
	}
	const want = "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f"
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		t.Errorf("subtree inclusion proof vector = %s, want %s", got, want)
	}
}

func TestSubtreeConsistencyProofVectors(t *testing.T) {
	tree := subtreeVectorTree()
	h := sha256.New()
	for n := 0; n <= subtreeVectorMax; n++ {
		for end := 1; end <= n; end++ {
			for start := 0; start < end; start++ {
				if !IsValidSubtree(start, end) {
					continue
				}
				proof, err := tree.SubtreeConsistencyProof(start, end, n)
				if err != nil {
					t.Fatalf("SubtreeConsistencyProof(%d, %d, %d): %v", start, end, n, err)
				}
				writeProofLine(h, fmt.Sprintf("[%d, %d) %d", start, end, n), proof)
			}
		}
	}
	const want = "c586ebbb73a5621baf2140095d87dde934e3b6503a562a1a5215b8209edd083d"
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		t.Errorf("subtree consistency proof vector = %s, want %s", got, want)
	}
}

func TestEfficientCoveringSubtreeVectors(t *testing.T) {
	h := sha256.New()
	for end := 1; end <= subtreeVectorMax; end++ {
		for start := 0; start < end; start++ {
			if end-start == 1 {
				fmt.Fprintf(h, "[%d, %d)\n", start, end)
				continue
			}
			start1, end1, start2, end2, err := SubtreesForInterval(start, end)
			if err != nil {
				t.Fatalf("SubtreesForInterval(%d, %d): %v", start, end, err)
			}
			fmt.Fprintf(h, "[%d, %d) [%d, %d)\n", start1, end1, start2, end2)
		}
	}
	const want = "1934dd9461c254b535c951661bb0d714ceec56720f06d5e6bf810cb058e6e3af"
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		t.Errorf("efficient covering subtree vector = %s, want %s", got, want)
	}
}
