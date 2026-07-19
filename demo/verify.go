package main

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

type repeatableString []string

func (s *repeatableString) String() string {
	return fmt.Sprintf("%v", *s)
}

func (s *repeatableString) Set(value string) error {
	*s = append(*s, value)
	return nil
}

var (
	verifyFlags = flag.NewFlagSet("verify", flag.ExitOnError)

	flagVersion = verifyFlags.String("version", "plants-05", "the draft version to target")
	flagPolicy  = verifyFlags.String("policy", "", "path to an optional certificate policy file")
	flagCACerts repeatableString

	mtcProofSigAlg []byte
)

func init() {
	verifyFlags.Var(&flagCACerts, "ca-cert", "path to a PEM file with one or more CA certificates, can be specified multiple times")

	b := cryptobyte.NewBuilder(nil)
	addMTCProofSigAlg(b)
	mtcProofSigAlg = b.BytesOrPanic()
}

func parseSerial(s string) (uint64, error) {
	if s == "max" {
		return math.MaxUint64, nil
	}
	if strings.Contains(s, ":") {
		parts := strings.Split(s, ":")
		if len(parts) != 2 {
			return 0, fmt.Errorf("invalid serial format %q", s)
		}
		logNum, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid log number in serial %q: %w", s, err)
		}
		index, err := strconv.ParseUint(parts[1], 10, 48)
		if err != nil {
			return 0, fmt.Errorf("invalid index in serial %q: %w", s, err)
		}
		return (logNum << 48) | index, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

func parsePolicyFile(policyPath string, policy *Policy) error {
	f, err := os.Open(policyPath)
	if err != nil {
		return fmt.Errorf("failed to open policy file %q: %w", policyPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		fields := strings.Fields(line)
		switch cmd := fields[0]; cmd {
		case "cosigner":
			if len(fields) != 4 {
				return fmt.Errorf("%s:%d: invalid cosigner command, expected 4 fields, got %d", policyPath, lineNum, len(fields))
			}
			id, ok := TrustAnchorIDFromString(fields[1])
			if !ok {
				return fmt.Errorf("%s:%d: invalid cosigner ID %q", policyPath, lineNum, fields[1])
			}
			sigAlg, ok := SignatureAlgorithmFromString(fields[2])
			if !ok {
				return fmt.Errorf("%s:%d: invalid signature algorithm %q", policyPath, lineNum, fields[2])
			}
			spki, err := base64.StdEncoding.DecodeString(fields[3])
			if err != nil {
				return fmt.Errorf("%s:%d: invalid base64 public key: %w", policyPath, lineNum, err)
			}
			if err := policy.AddCosigner(id, sigAlg, spki); err != nil {
				return fmt.Errorf("%s:%d: error adding cosigner: %w", policyPath, lineNum, err)
			}

		case "group":
			if len(fields) < 4 {
				return fmt.Errorf("%s:%d: invalid group command, expected at least 4 fields, got %d", policyPath, lineNum, len(fields))
			}
			groupName := fields[1]
			numStr := fields[2]
			members := fields[3:]
			var num int
			switch numStr {
			case "any":
				num = 1
			case "all":
				num = len(members)
			default:
				n, err := strconv.Atoi(numStr)
				if err != nil || n <= 0 || n > len(members) {
					return fmt.Errorf("%s:%d: invalid group number %q", policyPath, lineNum, numStr)
				}
				num = n
			}
			if err := policy.AddGroup(groupName, num, members); err != nil {
				return fmt.Errorf("%s:%d: error adding group: %w", policyPath, lineNum, err)
			}

		case "require-cosigners":
			if len(fields) != 3 {
				return fmt.Errorf("%s:%d: invalid require-cosigners command, expected 3 fields, got %d", policyPath, lineNum, len(fields))
			}
			caStr := fields[1]
			req := fields[2]
			if caStr == "all" {
				if err := policy.RequireCosignersForAllCAs(req); err != nil {
					return fmt.Errorf("%s:%d: error adding CA requirement: %w", policyPath, lineNum, err)
				}
			} else {
				caID, ok := TrustAnchorIDFromString(caStr)
				if !ok {
					return fmt.Errorf("%s:%d: invalid CA ID %q", policyPath, lineNum, caStr)
				}
				if err := policy.RequireCosignersForCA(caID, req); err != nil {
					return fmt.Errorf("%s:%d: error adding CA requirement: %w", policyPath, lineNum, err)
				}
			}

		case "revoke-range":
			if len(fields) != 4 {
				return fmt.Errorf("%s:%d: invalid revoke-range command, expected 4 fields, got %d", policyPath, lineNum, len(fields))
			}
			caID, ok := TrustAnchorIDFromString(fields[1])
			if !ok {
				return fmt.Errorf("%s:%d: invalid CA ID %q", policyPath, lineNum, fields[1])
			}
			minSerial, err := parseSerial(fields[2])
			if err != nil {
				return fmt.Errorf("%s:%d: invalid min serial: %w", policyPath, lineNum, err)
			}
			maxSerial, err := parseSerial(fields[3])
			if err != nil {
				return fmt.Errorf("%s:%d: invalid max serial: %w", policyPath, lineNum, err)
			}
			if err := policy.RevokeRange(caID, minSerial, maxSerial); err != nil {
				return fmt.Errorf("%s:%d: error adding revoke range: %w", policyPath, lineNum, err)
			}

		case "trusted-subtree":
			if len(fields) != 6 {
				return fmt.Errorf("%s:%d: invalid trusted-subtree command, expected 6 fields, got %d", policyPath, lineNum, len(fields))
			}
			caID, ok := TrustAnchorIDFromString(fields[1])
			if !ok {
				return fmt.Errorf("%s:%d: invalid CA ID %q", policyPath, lineNum, fields[1])
			}
			logNum, err := strconv.ParseUint(fields[2], 10, 16)
			if err != nil {
				return fmt.Errorf("%s:%d: invalid log number: %w", policyPath, lineNum, err)
			}
			start, err := strconv.ParseUint(fields[3], 10, 48)
			if err != nil {
				return fmt.Errorf("%s:%d: invalid start index: %w", policyPath, lineNum, err)
			}
			end, err := strconv.ParseUint(fields[4], 10, 48)
			if err != nil {
				return fmt.Errorf("%s:%d: invalid end index: %w", policyPath, lineNum, err)
			}
			hashBytes, err := base64.StdEncoding.DecodeString(fields[5])
			if err != nil || len(hashBytes) != HashSize {
				return fmt.Errorf("%s:%d: invalid hash (expected base64 %d bytes): %w", policyPath, lineNum, HashSize, err)
			}
			if err := policy.AddTrustedSubtree(caID, uint16(logNum), start, end, HashValue(hashBytes)); err != nil {
				return fmt.Errorf("%s:%d: error adding trusted subtree: %w", policyPath, lineNum, err)
			}

		default:
			return fmt.Errorf("%s:%d: unrecognized policy command %q", policyPath, lineNum, cmd)
		}
	}

	return scanner.Err()
}

func loadCACerts(paths []string, policy *Policy) error {
	for _, path := range paths {
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read CA cert file %q: %w", path, err)
		}
		for len(pemBytes) > 0 {
			var block *pem.Block
			block, pemBytes = pem.Decode(pemBytes)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse CA certificate from %q: %w", path, err)
			}
			if err := policy.AddCA(cert); err != nil {
				return fmt.Errorf("failed to add CA certificate: %w", err)
			}
		}
	}
	return nil
}

func verify(args []string) error {
	if err := verifyFlags.Parse(args); err != nil {
		return err
	}

	if len(flagCACerts) == 0 {
		return fmt.Errorf("no CA certificates specified (use -ca-cert)")
	}

	version, ok := DraftVersionFromString(*flagVersion)
	if !ok {
		return fmt.Errorf("unknown draft version %q", *flagVersion)
	}
	// Prior to plants-04, we didn't have a CA format in the first place.
	if version <= VersionPlants02 {
		return fmt.Errorf("unsupported draft version %q", version)
	}

	policy := Policy{Version: version}
	if err := loadCACerts(flagCACerts, &policy); err != nil {
		return err
	}
	if *flagPolicy != "" {
		if err := parsePolicyFile(*flagPolicy, &policy); err != nil {
			return err
		}
	}

	certPaths := verifyFlags.Args()
	if len(certPaths) == 0 {
		return fmt.Errorf("no certificate files specified to verify")
	}

	for _, certPath := range certPaths {
		pemBytes, err := os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("failed to read certificate file %q: %w", certPath, err)
		}
		numCerts := 0
		for len(pemBytes) > 0 {
			var block *pem.Block
			block, pemBytes = pem.Decode(pemBytes)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse certificate from %q: %w", certPath, err)
			}
			numCerts++
			result, err := VerifyMTCProof(cert, &policy, version)
			if err != nil {
				fmt.Printf("%s: %s\n", certPath, err)
			} else {
				fmt.Printf("%s: OK\n", certPath)
			}
			if result != nil {
				if result.TrustedSubtree {
					fmt.Printf("- Subtree was trusted\n")
				} else {
					if len(result.VerifyErrors) != 0 {
						fmt.Printf("- Signature verification errors:\n")
						for _, err := range result.VerifyErrors {
							fmt.Printf("    %s\n", err)
						}
					}
					fmt.Printf("- Cosigned by:\n")
					for i, b := range result.PolicyResult.Cosigners {
						if b {
							fmt.Printf("    %s\n", policy.Cosigners[i].ID)
						}
					}
					fmt.Printf("- Cosigner groups satisfied:\n")
					for i, b := range result.PolicyResult.Groups {
						if b {
							fmt.Printf("    %s\n", policy.Groups[i].Name)
						}
					}
					if len(result.UnsatisfiedRequirements) != 0 {
						fmt.Printf("- Unsatisfied requirements:\n")
						for _, req := range result.UnsatisfiedRequirements {
							fmt.Printf("    %s\n", policy.NameForIndex(req))
						}
					}
				}
			}
			fmt.Printf("\n")
		}
		if numCerts == 0 {
			return fmt.Errorf("%s: no certificates found in file", certPath)
		}
	}

	return nil
}
