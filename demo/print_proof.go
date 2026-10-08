package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

func formatHex(in []byte, verbose bool) string {
	if verbose || len(in) <= 32 {
		return hex.EncodeToString(in)
	}
	return fmt.Sprintf("%x...%x", in[:16], in[len(in)-16:])
}

func printProof(args []string) error {
	printProofFlags := flag.NewFlagSet("print-proof", flag.ExitOnError)
	flagVersion := printProofFlags.String("version", DefaultDraftVersion.String(), "the draft version to target")
	flagVerbose := printProofFlags.Bool("verbose", false, "Print the entirety of strings")
	if err := printProofFlags.Parse(args); err != nil {
		return err
	}

	version, ok := DraftVersionFromString(*flagVersion)
	if !ok {
		return fmt.Errorf("unknown draft version %q", *flagVersion)
	}

	certPaths := printProofFlags.Args()
	if len(certPaths) == 0 {
		return fmt.Errorf("no certificate files specified to print")
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
				fmt.Printf("Failed to parse certificate from %q: %s\n\n", certPath, err)
				continue
			}
			numCerts++

			proof, err := parseMTCProof(version, cert)
			if err != nil {
				fmt.Printf("Failed to parse MTCProof from %q: %s\n\n", certPath, err)
				continue
			}
			fmt.Printf("%s:\n", certPath)
			for _, ext := range proof.entryExts {
				fmt.Printf("- Entry extension type %d: %s\n", ext.extType, formatHex(ext.extValue, *flagVerbose))
			}
			fmt.Printf("- Inclusion proof:\n")
			const wrap = 32
			for i := 0; i < len(proof.inclusionProof); i += wrap {
				fmt.Printf("    %x\n", proof.inclusionProof[i:min(i+wrap, len(proof.inclusionProof))])
			}
			for _, sig := range proof.signatures {
				fmt.Printf("- Cosignature from %s: %s\n", sig.cosignerID, formatHex(sig.signature, *flagVerbose))
			}
			fmt.Printf("\n")
		}
		if numCerts == 0 {
			return fmt.Errorf("%s: no certificates found in file", certPath)
		}
	}

	return nil
}
