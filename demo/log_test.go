package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "updates saved test vector files")

func TestMerkleTree(t *testing.T) {
	const depth = 9
	const numEntries = 1 << depth

	entries := make([][]byte, numEntries)
	for i := range numEntries {
		entries[i] = []byte(fmt.Sprintf("entry %d", i))
	}
	tree := NewStaticMerkleTree(entries)

	for end := uint64(1); end <= numEntries; end++ {
		// Try all subtrees ending at `end`.
		for level := range depth {
			start := ((end - 1) >> level) << level
			subtreeHash, err := SubtreeHash(tree, start, end)
			if err != nil {
				t.Errorf("SubtreeHash(tree, %d, %d) unexpectedly failed: %s", start, end, err)
				continue
			}
			for index := start; index < end; index++ {
				entryHash := HashLeaf(entries[index])
				proof, err := SubtreeInclusionProof(tree, index, start, end)
				if err != nil {
					t.Errorf("SubtreeInclusionProof(tree, %d, %d, %d) unexpectedly failed: %s", index, start, end, err)
					continue
				}
				r, err := EvaluateSubtreeInclusionProof(index, start, end, &entryHash, proof)
				if err != nil {
					t.Errorf("EvaluateSubtreeInclusionProof(%d, %d, %d, %x, %x) unexpectedly failed: %s", index, start, end, entryHash[:], proof, err)
					continue
				}
				if !bytes.Equal(subtreeHash[:], r[:]) {
					t.Errorf("inclusion proof of entry %d in subtree [%d, %d) gave subtree hash of %x from entry hash %x, wanted %x", index, start, end, r[:], entryHash[:], subtreeHash[:])
				}
			}
		}
	}
}

func TestIsValidSubtree(t *testing.T) {
	// Small inputs for IsValidSubtree are exercised by TestSubtreeHashVectors.
	// This covers boundary conditions.
	var validSubtrees = []struct {
		start, end uint64
	}{
		{start: 0, end: (1 << 47) + 1},
		{start: 0, end: (1 << 48) - 1},
		{start: 0, end: (1 << 62) + 1},
		{start: 0, end: (1 << 63) - 1},
		{start: 0, end: (1 << 63) + 1},
		{start: 0, end: (1 << 64) - 1},
	}
	for _, tt := range validSubtrees {
		if !IsValidSubtree(tt.start, tt.end) {
			t.Errorf("IsValidSubtree(%d, %d) = false, want true", tt.start, tt.end)
		}
	}

	var invalidSubtrees = []struct {
		start, end uint64
	}{
		{start: 1 << 46, end: (1 << 47) + 1},
		{start: 1 << 46, end: (1 << 48) - 1},
		{start: 1 << 61, end: (1 << 62) + 1},
		{start: 1 << 61, end: (1 << 63) - 1},
		{start: 1 << 62, end: (1 << 63) + 1},
		{start: 1 << 62, end: (1 << 64) - 1},
	}
	for _, tt := range invalidSubtrees {
		if IsValidSubtree(tt.start, tt.end) {
			t.Errorf("IsValidSubtree(%d, %d) = true, want false", tt.start, tt.end)
		}
	}
}

func TestSubtreesForInterval(t *testing.T) {
	var tests = []struct {
		start, end   uint64
		start1, end1 uint64
		start2, end2 uint64
	}{
		{start: 9, end: 9, start1: 9, end1: 9, start2: 9, end2: 9},
		{start: 8, end: 9, start1: 8, end1: 9, start2: 9, end2: 9},
		{start: 5, end: 13, start1: 4, end1: 8, start2: 8, end2: 13},
		{start: 7, end: 9, start1: 7, end1: 8, start2: 8, end2: 9},
		{
			start: 0x0, end: 0x800000000000,
			start1: 0x0, end1: 0x400000000000,
			start2: 0x400000000000, end2: 0x800000000000,
		},
		{
			start: 0x500000000000, end: 0xd00000000000,
			start1: 0x400000000000, end1: 0x800000000000,
			start2: 0x800000000000, end2: 0xd00000000000,
		},
		{
			start: 0x7fffffffffff, end: 0x800000000001,
			start1: 0x7fffffffffff, end1: 0x800000000000,
			start2: 0x800000000000, end2: 0x800000000001,
		},
		{
			start: 0xfffffffffffe, end: 0xffffffffffff,
			start1: 0xfffffffffffe, end1: 0xffffffffffff,
			start2: 0xffffffffffff, end2: 0xffffffffffff,
		},
		{
			start: 0xffffffffffff, end: 0xffffffffffff,
			start1: 0xffffffffffff, end1: 0xffffffffffff,
			start2: 0xffffffffffff, end2: 0xffffffffffff,
		},
		{
			start: 0x0, end: 0x4000000000000000,
			start1: 0x0, end1: 0x2000000000000000,
			start2: 0x2000000000000000, end2: 0x4000000000000000,
		},
		{
			start: 0x2800000000000000, end: 0x6800000000000000,
			start1: 0x2000000000000000, end1: 0x4000000000000000,
			start2: 0x4000000000000000, end2: 0x6800000000000000,
		},
		{
			start: 0x3fffffffffffffff, end: 0x4000000000000001,
			start1: 0x3fffffffffffffff, end1: 0x4000000000000000,
			start2: 0x4000000000000000, end2: 0x4000000000000001,
		},
		{
			start: 0x7ffffffffffffffe, end: 0x7fffffffffffffff,
			start1: 0x7ffffffffffffffe, end1: 0x7fffffffffffffff,
			start2: 0x7fffffffffffffff, end2: 0x7fffffffffffffff,
		},
		{
			start: 0x7fffffffffffffff, end: 0x7fffffffffffffff,
			start1: 0x7fffffffffffffff, end1: 0x7fffffffffffffff,
			start2: 0x7fffffffffffffff, end2: 0x7fffffffffffffff,
		},
		{
			start: 0x0, end: 0x8000000000000000,
			start1: 0x0, end1: 0x4000000000000000,
			start2: 0x4000000000000000, end2: 0x8000000000000000,
		},
		{
			start: 0x5000000000000000, end: 0xd000000000000000,
			start1: 0x4000000000000000, end1: 0x8000000000000000,
			start2: 0x8000000000000000, end2: 0xd000000000000000,
		},
		{
			start: 0x7fffffffffffffff, end: 0x8000000000000001,
			start1: 0x7fffffffffffffff, end1: 0x8000000000000000,
			start2: 0x8000000000000000, end2: 0x8000000000000001,
		},
		{
			start: 0xfffffffffffffffe, end: 0xffffffffffffffff,
			start1: 0xfffffffffffffffe, end1: 0xffffffffffffffff,
			start2: 0xffffffffffffffff, end2: 0xffffffffffffffff,
		},
		{
			start: 0xffffffffffffffff, end: 0xffffffffffffffff,
			start1: 0xffffffffffffffff, end1: 0xffffffffffffffff,
			start2: 0xffffffffffffffff, end2: 0xffffffffffffffff,
		},
	}
	for _, tt := range tests {
		start1, end1, start2, end2, err := SubtreesForInterval(tt.start, tt.end)
		if err != nil {
			t.Errorf("SubtreesForInterval(%d, %d) unexpectedly failed: %s", tt.start, tt.end, err)
		} else if start1 != tt.start1 || end1 != tt.end1 || start2 != tt.start2 || end2 != tt.end2 {
			t.Errorf("SubtreesForInterval(%d, %d) gave [%d, %d) and [%d, %d), wanted [%d, %d) and [%d, %d)", tt.start, tt.end, start1, end1, start2, end2, tt.start1, tt.end1, tt.start2, tt.end2)
		}
	}
}

// A LargeMerkleTree simulates a larger Merkle Tree than fits in memory. It is
// given a set of leaf nodes to construct, each with value "Leaf N", and
// computes all nodes needed along the path to each node. Some subtree hashes
// will be filled with a fake deterministic value. Hashes not along the path to
// a target leaf may be unavailable due to a missing preimage.
type LargeMerkleTree struct {
	size   uint64
	levels []map[uint64]HashValue
}

func NewLargeMerkleTree(size uint64, indices []uint64) *LargeMerkleTree {
	mt := &LargeMerkleTree{size: size}
	leaves := map[uint64]HashValue{}
	makeLeaf := func(idx uint64) {
		leaves[idx] = HashLeaf([]byte(fmt.Sprintf("Leaf %d", idx)))
		// Also fill in the neighbor.
		if idx^1 < size {
			leaves[idx^1] = HashLeaf([]byte(fmt.Sprintf("Leaf %d", idx^1)))
		}
	}
	// Always construct the left and right edge.
	makeLeaf(0)
	makeLeaf(size - 1)
	for _, idx := range indices {
		makeLeaf(idx)
	}
	mt.levels = append(mt.levels, leaves)

	// Fill in subsequent levels.
	for levelSize := size; levelSize != 0; levelSize >>= 1 {
		prev := mt.levels[len(mt.levels)-1]
		level := map[uint64]HashValue{}
		// Fill in all hashes with known value.
		for idx := range prev {
			parent := idx >> 1
			if parent >= levelSize {
				continue
			}
			other := idx ^ 1
			left, right := prev[min(idx, other)], prev[max(idx, other)]
			level[parent] = HashNode(&left, &right)
		}
		// Synthesize neighbors of every node we filled in. These do not have
		// known preimages, so we assume their descendants are never accessed.
		for idx := range prev {
			other := (idx >> 1) ^ 1
			if other >= levelSize {
				continue
			}
			if _, ok := level[other]; ok {
				continue
			}
			h := sha256.New()
			h.Write([]byte{0x03})
			fmt.Fprintf(h, "Synthetic Node %d %d", len(mt.levels), other)
			level[other] = *((*[32]byte)(h.Sum(nil)))
		}
		mt.levels = append(mt.levels, level)
	}
	return mt
}

func (mt *LargeMerkleTree) Size() uint64 { return mt.size }

func (mt *LargeMerkleTree) FullSubtreeHashByLevel(level int, idx uint64) HashValue {
	hash, ok := mt.levels[level][idx]
	if !ok {
		// This panic will trip if some Merkle Tree algorithm uses a node we didn't
		// compute the tree with.
		var b strings.Builder
		fmt.Fprintf(&b, "could not find node at level %d and index 0x%x, (available: ", level, idx)
		for i, key := range slices.Sorted(maps.Keys(mt.levels[level])) {
			if i != 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "0x%x", key)
		}
		b.WriteString(")")
		panic(b.String())
	}
	return hash
}

func alternatingBits(n int) uint64 {
	return uint64(0xaaaa_aaaa_aaaa_aaaa) >> (64 - n)
}

func mustDecodeHex(s string) []byte {
	ret, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return ret
}

func checkOrUpdateTestVectors(t *testing.T, path string, contents []byte) {
	if *update {
		if err := os.WriteFile(path, contents, 0644); err != nil {
			t.Fatalf("could not write %q: %s", path, err)
		}
	} else {
		expected, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("could not read %q: %s", path, err)
		}
		if !bytes.Equal(contents, expected) {
			t.Errorf("test vector file did not match, pass -update to update")
		}
	}
}

type inclusionProofVector struct {
	Index, Start, End             uint64
	EntryHash, SubtreeHash, Proof []byte
}

func TestLargeInclusionProofs(t *testing.T) {
	pow2 := func(n int) uint64 { return uint64(1) << n }

	var text bytes.Buffer
	var vectors []inclusionProofVector
	subtest := func(tree MerkleTree, index, start, end uint64) {
		t.Run(fmt.Sprintf("index_%x_start_%x_end_%x", index, start, end), func(t *testing.T) {
			subtreeHash, err := SubtreeHash(tree, start, end)
			if err != nil {
				t.Fatalf("SubtreeHash(tree, %d, %d) unexpectedly failed: %s", start, end, err)
			}
			entryHash := tree.FullSubtreeHashByLevel(0, index)
			proof, err := SubtreeInclusionProof(tree, index, start, end)
			if err != nil {
				t.Fatalf("SubtreeInclusionProof(tree, %d, %d, %d) unexpectedly failed: %s", index, start, end, err)
			}
			r, err := EvaluateSubtreeInclusionProof(index, start, end, &entryHash, proof)
			if err != nil {
				t.Fatalf("EvaluateSubtreeInclusionProof(%d, %d, %d, %x, %x) unexpectedly failed: %s", index, start, end, entryHash[:], proof, err)
			}
			if !bytes.Equal(subtreeHash[:], r[:]) {
				t.Errorf("inclusion proof of entry %d in subtree [%d, %d) gave subtree hash of %x from entry hash %x, wanted %x", index, start, end, r[:], entryHash[:], subtreeHash[:])
			}

			vectors = append(vectors, inclusionProofVector{
				Index:       index,
				Start:       start,
				End:         end,
				EntryHash:   entryHash[:],
				SubtreeHash: subtreeHash[:],
				Proof:       proof,
			})
			fmt.Fprintf(&text, "Entry index 0x%x with hash %x\n", index, entryHash)
			fmt.Fprintf(&text, "Subtree [0x%x, 0x%x) with hash %x\n", start, end, subtreeHash)
			fmt.Fprintf(&text, "Inclusion Proof:\n")
			for start := 0; start < len(proof); start += 32 {
				fmt.Fprintf(&text, "  %x\n", proof[start:start+32])
			}
			fmt.Fprintf(&text, "\n")
		})
	}

	text.WriteString("Also available in machine-readable form in large_inclusion_proofs.json\n\n")

	for _, n := range []int{48, 63, 64} {
		t.Run(fmt.Sprintf("%d_bits", n), func(t *testing.T) {
			fmt.Fprintf(&text, "Test vectors for a tree of size 2^%d-1:\n\n", n)

			// Exercise a subtree of maximum height.
			start1 := uint64(0)
			// Exercise a non-trivial starting point.
			start2 := pow2(n - 1)
			// This value looks like 0b11...1100..00100...00. It is significantly on the
			// right edge, has significant left turns, and ends at a significant
			// complete subtree.
			end := pow2(n) - pow2(n/2) + pow2(n/4)
			// An interesting value (0b1010101010...) between start2 and end.
			index1 := alternatingBits(n)
			// An interesting value inside end's complete subtree.
			index2 := pow2(n) - pow2(n/2) + alternatingBits(n/4)

			tree := NewLargeMerkleTree(pow2(n)-1, []uint64{start1, start2, end - 1, index1, index2})

			subtest(tree, start1, start1, end)
			subtest(tree, index1, start1, end)
			subtest(tree, index2, start1, end)
			subtest(tree, end-1, start1, end)

			subtest(tree, start2, start2, end)
			subtest(tree, index1, start2, end)
			subtest(tree, index2, start2, end)
			subtest(tree, end-1, start2, end)
		})
	}

	checkOrUpdateTestVectors(t, "large_inclusion_proofs.txt", text.Bytes())
	vectorsJSON, err := json.Marshal(vectors, json.StringifyNumbers(true), jsontext.WithIndent("  "))
	if err != nil {
		t.Fatalf("could not write JSON: %s", err)
	}
	checkOrUpdateTestVectors(t, "large_inclusion_proofs.json", vectorsJSON)
}

type consistencyProofVector struct {
	Start, End, TreeSize         uint64
	SubtreeHash, TreeHash, Proof []byte
}

func TestLargeConsistencyProofs(t *testing.T) {
	pow2 := func(n int) uint64 { return uint64(1) << n }

	var text bytes.Buffer
	var vectors []consistencyProofVector
	subtest := func(tree MerkleTree, start, end, treeSize uint64) {
		t.Run(fmt.Sprintf("start_%x_end_%x_size_%x", start, end, treeSize), func(t *testing.T) {
			subtreeHash, err := SubtreeHash(tree, start, end)
			if err != nil {
				t.Fatalf("SubtreeHash(tree, %d, %d) unexpectedly failed: %s", start, end, err)
			}
			treeHash, err := SubtreeHash(tree, 0, treeSize)
			if err != nil {
				t.Fatalf("SubtreeHash(tree, 0, %d) unexpectedly failed: %s", treeSize, err)
			}
			proof, err := SubtreeConsistencyProof(tree, start, end, treeSize)
			if err != nil {
				t.Fatalf("SubtreeConsistencyProof(tree, %d, %d, %d) unexpectedly failed: %s", start, end, treeSize, err)
			}

			vectors = append(vectors, consistencyProofVector{
				Start:       start,
				End:         end,
				TreeSize:    treeSize,
				SubtreeHash: subtreeHash[:],
				TreeHash:    treeHash[:],
				Proof:       proof,
			})
			fmt.Fprintf(&text, "Subtree [0x%x, 0x%x) with hash %x\n", start, end, subtreeHash)
			fmt.Fprintf(&text, "Tree size 0x%x with hash %x\n", treeSize, treeHash)
			fmt.Fprintf(&text, "Consistency Proof:\n")
			for start := 0; start < len(proof); start += 32 {
				fmt.Fprintf(&text, "  %x\n", proof[start:start+32])
			}
			fmt.Fprintf(&text, "\n")
		})
	}

	text.WriteString("Also available in machine-readable form in large_consistency_proofs.json\n\n")

	for _, n := range []int{48, 63, 64} {
		t.Run(fmt.Sprintf("%d_bits", n), func(t *testing.T) {
			fmt.Fprintf(&text, "Test vectors for a tree of size 2^%d-2^%d+2^%d:\n\n", n, n/2, n/4)

			// Use an incomplete tree of size 0b11...1100..00100...00 with skipped
			// levels on the right edge and multiple split points.
			treeSize := pow2(n) - pow2(n/2) + pow2(n/4)
			start1 := uint64(0)
			start2 := pow2(n - 1)
			// A complete power-of-2 prefix deep in the left child.
			startPow2 := pow2(n / 2)
			// The split point before the final complete subtree.
			mid := pow2(n) - pow2(n/2)

			tree := NewLargeMerkleTree(treeSize, []uint64{start2, startPow2 - 1, mid - 1, mid})

			// Empty subtree.
			subtest(tree, start1, start1, treeSize)
			// Whole tree.
			subtest(tree, start1, treeSize, treeSize)
			// Complete power-of-2 prefix.
			subtest(tree, start1, startPow2, treeSize)
			// Incomplete prefix, decomposing the subtree's right edge.
			subtest(tree, start1, mid, treeSize)
			// Complete subtree touching the right edge.
			subtest(tree, mid, treeSize, treeSize)
			// Interior incomplete subtree, decomposing within the right child.
			subtest(tree, start2, mid, treeSize)
			// Single leaf at the right edge, matching an inclusion proof.
			subtest(tree, treeSize-1, treeSize, treeSize)

		})
	}

	checkOrUpdateTestVectors(t, "large_consistency_proofs.txt", text.Bytes())
	vectorsJSON, err := json.Marshal(vectors, json.StringifyNumbers(true), jsontext.WithIndent("  "))
	if err != nil {
		t.Fatalf("could not write JSON: %s", err)
	}
	checkOrUpdateTestVectors(t, "large_consistency_proofs.json", vectorsJSON)
}
