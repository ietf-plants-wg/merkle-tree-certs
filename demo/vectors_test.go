package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"slices"
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
	for end := uint64(0); end <= subtreeVectorMax; end++ {
		for start := uint64(0); start <= end; start++ {
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
	const want = "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81"
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		t.Errorf("subtree hash vector = %s, want %s", got, want)
	}
}

func TestSubtreeInclusionProofVectors(t *testing.T) {
	tree := subtreeVectorTree()
	h := sha256.New()
	for end := uint64(0); end <= subtreeVectorMax; end++ {
		for start := uint64(0); start <= end; start++ {
			if !IsValidSubtree(start, end) {
				continue
			}
			subtreeHash, err := tree.SubtreeHash(start, end)
			if err != nil {
				t.Fatalf("SubtreeHash(%d, %d): %v", start, end, err)
			}
			for index := start; index < end; index++ {
				proof, err := tree.SubtreeInclusionProof(index, start, end)
				if err != nil {
					t.Fatalf("SubtreeInclusionProof(%d, %d, %d): %v", index, start, end, err)
				}
				writeProofLine(h, fmt.Sprintf("%d [%d, %d)", index, start, end), proof)

				entryHash := HashLeaf([]byte{byte(index)})
				got, err := EvaluateSubtreeInclusionProof(index, start, end, &entryHash, proof)
				if err != nil {
					t.Errorf("EvaluateSubtreeInclusionProof(%d, %d, %d): %v", index, start, end, err)
				} else if got != subtreeHash {
					t.Errorf("EvaluateSubtreeInclusionProof(%d, %d, %d) = %x, want %x", index, start, end, got, subtreeHash)
				}

				if len(proof) > 0 {
					if _, err := EvaluateSubtreeInclusionProof(index, start, end, &entryHash, proof[:len(proof)-1]); err == nil {
						t.Errorf("EvaluateSubtreeInclusionProof(%d, %d, %d) unexpectedly succeeded with proof truncated by one byte", index, start, end)
					}
				}
				if len(proof) >= HashSize {
					if _, err := EvaluateSubtreeInclusionProof(index, start, end, &entryHash, proof[:len(proof)-HashSize]); err == nil {
						t.Errorf("EvaluateSubtreeInclusionProof(%d, %d, %d) unexpectedly succeeded with proof truncated by a full hash", index, start, end)
					}
				}

				extendedByte := slices.Concat(proof, []byte{0})
				if _, err := EvaluateSubtreeInclusionProof(index, start, end, &entryHash, extendedByte); err == nil {
					t.Errorf("EvaluateSubtreeInclusionProof(%d, %d, %d) unexpectedly succeeded with proof extended by one byte", index, start, end)
				}

				extendedHash := slices.Concat(proof, make([]byte, HashSize))
				if _, err := EvaluateSubtreeInclusionProof(index, start, end, &entryHash, extendedHash); err == nil {
					t.Errorf("EvaluateSubtreeInclusionProof(%d, %d, %d) unexpectedly succeeded with proof extended by a full hash", index, start, end)
				}
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
	for n := uint64(0); n <= subtreeVectorMax; n++ {
		for end := uint64(0); end <= n; end++ {
			for start := uint64(0); start <= end; start++ {
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
	const want = "10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74"
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		t.Errorf("subtree consistency proof vector = %s, want %s", got, want)
	}
}

func TestEfficientCoveringSubtreeVectors(t *testing.T) {
	h := sha256.New()
	for end := uint64(0); end <= subtreeVectorMax; end++ {
		for start := uint64(0); start <= end; start++ {
			start1, end1, start2, end2, err := SubtreesForInterval(start, end)
			if err != nil {
				t.Fatalf("SubtreesForInterval(%d, %d): %v", start, end, err)
			}
			fmt.Fprintf(h, "[%d, %d) [%d, %d)\n", start1, end1, start2, end2)
		}
	}
	const want = "7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0"
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != want {
		t.Errorf("efficient covering subtree vector = %s, want %s", got, want)
	}
}
