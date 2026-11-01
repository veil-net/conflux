// Package pki is conflux's certificate toolkit: keys, requests, certificates and revocation
// lists, issued and checked with post-quantum signatures by default and the approved
// classical ones beside them.
//
// Every key, signature, hash, KDF and cipher here is the Go Cryptographic Module's, used as
// its Security Policy approves: each is a service module v1.0.0 (CMVP #5247) approves, with
// ML-DSA the one exception, as docs/security.md "FIPS 140-3 and CMVP" says, and every command
// refuses to run where the module is not in FIPS 140-3 mode (fips.go). approved_test.go holds
// the source to it.
package pki
