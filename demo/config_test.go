package main

import (
	"bytes"
	"testing"
)

func TestTrustAnchorID(t *testing.T) {
	invalidTests := []string{"nope", "-1.-1", "1..2", "1.", ".1", "4294967296"}
	for _, test := range invalidTests {
		_, ok := TrustAnchorIDFromString(test)
		if ok {
			t.Errorf("TrustAnchorIDFromString(%q) unexpectedly succeeded", test)
		}
	}

	var validTests = []struct {
		str string
		id  []byte
	}{
		{"32473.1", []byte{0x81, 0xfd, 0x59, 0x01}},
		{"4294967295", []byte{0x8f, 0xff, 0xff, 0xff, 0x7f}},
	}
	for _, tt := range validTests {
		id, ok := TrustAnchorIDFromString(tt.str)
		if !ok {
			t.Errorf("TrustAnchorIDFromString(%q) unexpectedly failed", tt.str)
			continue
		}
		if !bytes.Equal(id, tt.id) {
			t.Errorf("TrustAnchorIDFromString(%q) was %x, wanted %x", tt.str, []byte(id), tt.id)
			continue
		}
		if id.String() != tt.str {
			t.Errorf("id.String() was %s, wanted %s", id, tt.str)
			continue
		}
	}
}

func TestTrustAnchorIDPattern(t *testing.T) {
	invalidTests := []string{"nope", "-1.-1", "1..2", "1.", ".1", "4294967296", "{-1}", "{1-2", "1-2}", "{1-2-3}", "{1}"}
	for _, test := range invalidTests {
		_, ok := TrustAnchorIDPatternFromString(test)
		if ok {
			t.Errorf("TrustAnchorIDPatternFromString(%q) unexpectedly succeeded", test)
		}
	}

	var validTests = []struct {
		str     string
		pattern []byte
	}{
		{"32473.1", []byte{0x81, 0xfd, 0x59, 0x81, 0xfd, 0x59, 0x01, 0x01}},
		{"4294967295", []byte{0x8f, 0xff, 0xff, 0xff, 0x7f, 0x8f, 0xff, 0xff, 0xff, 0x7f}},
		{"32473.{123-456}.{789-}", []byte{0x81, 0xfd, 0x59, 0x81, 0xfd, 0x59, 0x7b, 0x83, 0x48, 0x86, 0x15, 0x80}},
	}
	for _, tt := range validTests {
		pattern, ok := TrustAnchorIDPatternFromString(tt.str)
		if !ok {
			t.Errorf("TrustAnchorIDPatternFromString(%q) unexpectedly failed", tt.str)
			continue
		}
		if !bytes.Equal(pattern, tt.pattern) {
			t.Errorf("TrustAnchorIDPatternFromString(%q) was %x, wanted %x", tt.str, []byte(pattern), tt.pattern)
			continue
		}
		if pattern.String() != tt.str {
			t.Errorf("id.String() was %s, wanted %s", pattern, tt.str)
			continue
		}
	}
}

func TestTrustAnchorIDToPattern(t *testing.T) {
	id := TrustAnchorID{0x81, 0xfd, 0x59, 0x01}
	pattern := TrustAnchorIDToPattern(id)
	expected := TrustAnchorIDPattern{0x81, 0xfd, 0x59, 0x81, 0xfd, 0x59, 0x01, 0x01}
	if !bytes.Equal(id, pattern) {
		t.Errorf("TrustAnchorIDToPattern(%s) was %s, wanted %s", id, pattern, expected)
	}
}
