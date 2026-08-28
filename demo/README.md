# Merkle Tree Certificates Demo

This tool includes a demo Merkle Tree Certificates generator and verifier. To build it, install [Go 1.27 or later](https://go.dev/) and run `go build` from this directory. From there, there are two subcommands:

* `./demo generate` to [generate test certificates](#generating-certificates)
* `./demo verify` to [verify certificates](#verifying-certificates)

## Generating Certificates

The `generate` subcommand generates a corpus of test certificates based on a JSON config file. By default, it reads from `mtc.json` and writes to `out`. This can be reconfigured with the `-config` and `-out` flags.

The JSON config file defines all entries in the simulated CA's issuance log, as well as which signatures to generate based on the log.
It outputs:

* `tile` and `checkpoint` files containing the issuance log in [tlog-tiles](https://c2sp.org/tlog-tiles) format.

* `ca_cert.pem` describing the CA as an X.509 certificate.

* `cert_{entry}_{num}.pem` containing a certificate for the specified entry.

For the full schema of the configuration file, see `config.go`. There is an example configuration in `mtc.json`. This document describes the overall structure:

### Root Dictionary

The root of the JSON file defines an MTC CA and any global configuration. Some important keys are:

* `Version`: The draft version to implement.
* `ID`: The CA ID, in dotted decimal form.
* `LogNumber`: The log number for the CA.
* `Cosigners`: An array of available cosigners, named by ID. Cosigner private keys are base64-encoded PKCS#8 [PrivateKeyInfo](https://www.rfc-editor.org/info/rfc5208/) structures.
* `CACert` describes the fields to encode in the CA certificate.
* `Entries` describes the entries to add to the issuance log.

### Entry Dictionaries

Each element of `Entries` is a JSON dictionary that adds to one or more entries in the issuance log. By default, it adds only one entry, but the `Repeat` key can add additional ones. The added entries have type `tbs_cert_entry`, unless the `Null` key is set, which adds a `null_entry` instead.

Most fields in an entry dictionary correspond to fields in X.509, to be added to the TBSCertificate. The `PublicKey` field specifies the SubjectPublicKeyInfo encoded in base64.

Each entry dictionary additionally specifies the positions of checkpoints and any certificates to output for this entry. They are described below.

### Checkpoints

The test CA maintains a number of *checkpoint sequences*. Each checkpoint sequence is named by some string and contains a series of monotonically increasing tree sizes.

The `Checkpoints` field of an entry dictionary is a list of strings, with the names of checkpoint sequences to append to. After adding the entry to the log, the tool appends the current tree size to each of the named checkpoint sequences.

To simulate a real CA, maintain two checkpoint sequences: `standalone` and `landmark`.

* The `standalone` sequence simulates standalone certificate issuance. A real CA validates issuance requests and then adds them to the log. It then periodically requests cosignatures for the current state of the log. It finally constructs standalone certificates with cosigned subtrees [based on](https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-efficiently-covering-arbitr) the interval of entries added since the last batch. Standalone batches may be every few seconds, or even after every individual entry.

* The `landmark` sequence simulates landmark-relative certificate issuance. A real CA would periodically add the current tree size to its landmark sequence. It then issues landmark-relative certificates [based on](https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-efficiently-covering-arbitr) the range of entries between consecutive landmarks.

Sequence names in this tool, however, are arbitrary, except that the sequence named `landmark` is summarized at the end of the tool, to output the landmark subtrees for this log. Otherwise, the JSON file can define any number of checkpoint sequences of any name. Checkpoint sequences are incorporated into certificates as described below.

### Certificates

Each Merkle Tree Certificate is defined by the following:

* An entry with the information being certified
* A subtree containing that entry
* Zero or more cosignatures of that subtree

If there are sufficient cosignatures to satisfy the relying party, it is a standalone certificate. If the relying party has prior knowledge of this subtree, by way of predistributed landmarks, it is a landmark-relative certificate.

By convention, a real CA is expected to pick subtrees and cosignatures as described in the previous section. However, to help in generating test data, this tool supports arbitrary subtree and cosignature inputs.

Each entry dictionary has a `Certificates` field, which contains a list of certificate configurations. Each of these will output a certificate into `cert_{entry}_{num}.pem` file. `entry` is the zero-based index of the entry, and `num` is the zero-based index of the certificate configuration.

Each certificate configuration is a JSON dictionary. It defines the subtree in one of two ways:

* `SubtreeStart` and `SubtreeEnd` fields that specify the exact subtree.

* A `Checkpoint` field with the name of a checkpoint sequence. In this case the subtree is implicitly determined from the interval between checkpoints that contains this entry. For example, if the entry has index 8, the `Checkpoint` field is `foo`, and the `foo` sequence is 0, 5, 10, 15, the subtree is [based on](https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-efficiently-covering-arbitr) the interval [5, 10).

The certificate configuration's `Cosigners` field contains the list of cosigners, by ID, to sign the subtree. The list may be empty, or omitted, to include no cosignatures. In this case, the certificate will only be accepted if the relying party has prior knowledge of the subtree.

## Verifying Certificates

The `verify` subcommand verifies MTCProofs in a certificate. It takes a number of flags:

* `-version`: The draft version to implement.
* `-ca-cert`: The path to a set of CA certificates in PEM form. This flag can be repeated to combine multiple files.
* `-policy`: The path to an optional policy file.

It then takes paths to certificates to verify, also in PEM form, as positional arguments, and outputs whether each of them was valid.

By default, the tool only supports standalone certificates, looking only for a CA cosignature. Other cosignatures are ignored. The optional policy file overrides this behavior and can specify:

* Additional cosigner requirements on standalone certificates
* Trusted subtrees to accept landmark-relative certificates

See the sample `policy.txt` file for more details and an example. The trusted subtrees list can be populated from the output of the `generate` subcommand.

**WARNING**: The `verify` subcommand *only* verifies the MTCProof structure. It is not a complete X.509 path validator. It does not check any non-MTC X.509 mechanisms such as `notBefore` and `notAfter`, constraints, critical extensions, etc. Those mechanisms are unchanged by MTC.


