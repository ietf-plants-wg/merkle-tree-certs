package main

import (
	"bytes"
	"fmt"
	"testing"
)

func evaluateSubtreeInclusionProof(index, start, end int, entryHash *HashValue, proof []byte) (HashValue, error) {
	if !IsValidSubtree(start, end) {
		return HashValue{}, fmt.Errorf("invalid subtree")
	}
	if start > index || index >= end {
		return HashValue{}, fmt.Errorf("index not in subtree")
	}
	fn := index - start
	sn := end - start - 1
	r := *entryHash
	for len(proof) != 0 {
		if len(proof) < HashSize {
			return HashValue{}, fmt.Errorf("truncated hash in proof")
		}
		p := (*HashValue)(proof)
		proof = proof[HashSize:]
		if sn == 0 {
			return HashValue{}, fmt.Errorf("proof too long")
		}
		if fn&1 == 1 || fn == sn {
			r = HashNode(p, &r)
			for fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = HashNode(&r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return HashValue{}, fmt.Errorf("proof too short")
	}
	return r, nil
}

func TestMerkleTree(t *testing.T) {
	const depth = 9
	const numEntries = 1 << depth

	entries := make([][]byte, numEntries)
	for i := range numEntries {
		entries[i] = []byte(fmt.Sprintf("entry %d", i))
	}
	tree := NewMerkleTree(entries)

	for end := 1; end <= numEntries; end++ {
		// Try all subtrees ending at `end`.
		for level := range depth {
			start := ((end - 1) >> level) << level
			subtreeHash, err := tree.SubtreeHash(start, end)
			if err != nil {
				t.Errorf("tree.SubtreeHash(%d, %d) unexpectedly failed: %s", start, end, err)
				continue
			}
			for index := start; index < end; index++ {
				entryHash := HashLeaf(entries[index])
				proof, err := tree.SubtreeInclusionProof(index, start, end)
				if err != nil {
					t.Errorf("tree.SubtreeInclusionProof(%d, %d, %d) unexpectedly failed: %s", index, start, end, err)
					continue
				}
				r, err := evaluateSubtreeInclusionProof(index, start, end, &entryHash, proof)
				if err != nil {
					t.Errorf("evaluateSubtreeInclusionProof(%d, %d, %d, %x, %x) unexpectedly failed: %s", index, start, end, entryHash[:], proof, err)
					continue
				}
				if !bytes.Equal(subtreeHash[:], r[:]) {
					t.Errorf("inclusion proof of entry %d in subtree [%d, %d) gave subtree hash of %x from entry hash %x, wanted %x", index, start, end, r[:], entryHash[:], subtreeHash[:])
				}
			}
		}
	}
}

func TestSubtreesForInterval(t *testing.T) {
	var tests = []struct {
		start, end   int
		start1, end1 int
		start2, end2 int
	}{
		{start: 9, end: 9, start1: 9, end1: 9, start2: 9, end2: 9},
		{start: 8, end: 9, start1: 8, end1: 9, start2: 9, end2: 9},
		{start: 5, end: 13, start1: 4, end1: 8, start2: 8, end2: 13},
		{start: 7, end: 9, start1: 7, end1: 8, start2: 8, end2: 9},
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
