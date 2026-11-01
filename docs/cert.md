# Certificates

`conflux cert` makes and checks X.509: private keys, certificate signing requests,
certificates and revocation lists, and the TLS handshakes they are used in. It covers the part
of OpenSSL's `genpkey`, `req`, `x509`, `ca`, `verify`, `crl`, `pkcs8`, `s_client` and
`s_server` that a certificate authority and its users need, and keeps a CA's records, and it does it post-quantum
first. Keys are ML-DSA-87 unless asked otherwise, and a chain can be ML-DSA
from the root to the leaf.

Every key, signature, digest, KDF and cipher here belongs to the Go Cryptographic Module,
running in FIPS 140-3 mode. Each is a service that the Security Policy of module v1.0.0
(CMVP #5247) approves, with ML-DSA the one exception; [security.md](security.md#fips-140-3-and-cmvp)
says exactly what may be claimed. A conflux not running in that mode (OpenBSD's, which is
built without the module) refuses every `cert` command with exit 70. These are artifacts
other people rely on, and the claim has to hold for every one of them.

`conflux cert` needs no root, no configuration and no anchor. It touches only the files it
is named, and the network only for `probe` and `serve`.

## A certificate authority in five commands

```sh
# An ML-DSA-87 root, its key encrypted under a passphrase asked at the terminal
conflux cert genkey --encrypt --out root.key
conflux cert selfsign --key root.key --subject "/O=Example/CN=Example Root" --out root.pem

# A server's key and request (on the server), and its certificate (at the CA)
conflux cert genkey --alg ml-dsa-65 --out server.key
conflux cert req --key server.key --subject CN=server.example --san 192.0.2.10 --out server.csr
conflux cert sign --csr server.csr --ca root.pem --ca-key root.key --days 90 --out server.pem

conflux cert verify server.pem --ca root.pem --name server.example --purpose server --require-pq
```

`verify` answers `Valid` and the chain. Every link is ML-DSA, so `authentication` is `pqc`.

Revoking a certificate later takes its serial, as `show` prints it:

```sh
conflux cert crl --ca root.pem --ca-key root.key --revoke 41:24:71:…:AB:keyCompromise --out root.crl
conflux cert verify server.pem --ca root.pem --crl root.crl       # exit 3: revoked
```

## Algorithms

| `--alg` | Key | Signs certificates with |
|---|---|---|
| `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` (the default) | ML-DSA, FIPS 204 | ML-DSA itself, pure |
| `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521` | ECDSA, FIPS 186-5 | ECDSA with SHA-256, SHA-384 or SHA-512, by curve |
| `rsa-2048`, `rsa-3072`, `rsa-4096` | RSA, FIPS 186-5 | PKCS #1 v1.5 with SHA-256, SHA-384 or SHA-512, by size; `--rsa-pss` for RSASSA-PSS |
| `ed25519` | EdDSA, FIPS 186-5 | Ed25519, pure |

A certificate is signed with whatever its *issuer's* key pairs with. So an ML-DSA root
signs an ECDSA leaf with ML-DSA: the chain is mixed, and its authentication is classical (see
[Verifying](#verifying)). There are no composite (hybrid) ML-DSA certificates. They are still
IETF drafts, and Go does not make them; a mixed chain is the way to have both.

## Keys

- **Form.** Keys are PKCS#8 (RFC 5958). An ML-DSA key is written as its 32-byte seed, RFC 9881's
  seed form: FIPS 204 rebuilds the whole key from the seed. The form OpenSSL 3.5 writes by
  default, with the seed beside the expanded key, is read too. Its expanded half is checked
  against the seed (ρ, K and tr, which SHAKE256 alone reproduces), so a file whose two halves
  are different keys is refused rather than read as one of them. A key with no seed at all
  (OpenSSL's `priv-only`) cannot be read: nothing can recover a seed.
- **Older forms.** An EC or RSA key in its pre-PKCS#8 form (`EC PRIVATE KEY`, `RSA PRIVATE KEY`)
  is read as the same key. `convert` writes it out as PKCS#8.
- **Writing.** A key in the clear is written mode 0600 (owner-only on Windows), atomically. It is
  never written over a file already there without `--force`, since a key overwritten is lost.
  It is never printed to a terminal either. `--out -` prints to stdout only when stdout is not a
  terminal.

### Encrypted keys

`--encrypt` (on `genkey` and `convert`) writes a PKCS#8 EncryptedPrivateKeyInfo under PBES2
(RFC 8018):

| | Written | Read |
|---|---|---|
| Key derivation | PBKDF2 with HMAC-SHA-256, 600,000 iterations, a 16-byte salt | PBKDF2 with HMAC-SHA-224, -256, -384 or -512, a salt of 16 bytes or more |
| Cipher | AES-256-CBC | AES-128, -192 or -256 in CBC |

Anything else is refused by name, before a passphrase is used: PBES1, PKCS#12's own schemes,
DES, 3DES, RC2, RC4, MD5, PBKDF2 with HMAC-SHA-1 (the default when a file names no PRF), scrypt,
a salt under 16 bytes, and OpenSSL's legacy encrypted PEM (`Proc-Type: 4,ENCRYPTED`, a key MD5
derives). The refusal gives the line that re-encrypts the key without ever writing it in the
clear:

```sh
openssl pkey -in KEY | conflux cert convert - --encrypt --out KEY.new
```

OpenSSL before 3.2 writes an 8-byte salt and cannot be asked for more, so its encrypted keys
are among those refused. The line above works with any OpenSSL version.

**Passphrases** come from `--passphrase-file FILE` (its first line), `--passphrase-env NAME`,
or a prompt with echo off. The prompt reads the controlling terminal itself rather than stdin,
so a key can be piped in while its passphrase is typed. A passphrase is never taken from a
flag's own value, which every process on the machine can read. `convert` takes the old one
through `--passphrase-*` and the new one through `--new-passphrase-*`. A new passphrase is at
least 8 characters, and is asked twice.

## Names

`--subject` takes a distinguished name written either way round:

- OpenSSL's, most general first: `/C=AU/O=Example/CN=host.example`;
- RFC 4514's, most specific first: `CN=host.example,O=Example,C=AU`.

Both encode the same, most general first. The attributes are `CN`, `O`, `OU`, `C` (two
capitals), `ST`, `L`, `STREET`, `POSTALCODE`, `SERIALNUMBER`, `DC`, `UID` and `emailAddress`. A
comma, slash, plus, equals or backslash inside a value takes a backslash in front.

`--san` adds a subject alternative name, and repeats:

- typed, as `DNS:`, `IP:`, `EMAIL:` or `URI:`;
- or bare, its type read from its shape: an address, something with `://`, something with `@`,
  or else a DNS name.

A wildcard is allowed as the leftmost label only, and under at least two labels. With no
`--san`, a server certificate or a request takes its CN as its one name, if that CN is a host
name or an address, and says so; TLS clients check names, not CNs.

## Profiles

`--profile` decides what a certificate may be used for. A request asks only for its subject
and its names; nothing else in it is copied.

| Profile | Key usage | Extended key usage | Basic constraints |
|---|---|---|---|
| `server` (sign's default) | digitalSignature, and keyEncipherment for RSA | serverAuth | not a CA |
| `client` | the same | clientAuth | not a CA |
| `server+client` | the same | serverAuth, clientAuth | not a CA |
| `ca` (selfsign's default) | keyCertSign, cRLSign, digitalSignature | — | a CA; `--path-len N` bounds the CAs below it |

Every certificate carries a random 128-bit serial and RFC 7093's subject key identifier (the
first 160 bits of SHA-256 over the key). It carries its issuer's as its authority key
identifier. Its validity starts five minutes back, for clocks a little behind, and lasts
`--days`: 3650 for a self-signed CA, 365 otherwise. A certificate may not outlive its issuer.
Asking for one that would is refused, naming the most days it could have. `--crl-url`
records where the issuer's revocation list is published.

## Commands

| Command | |
|---|---|
| `genkey --out FILE [--alg ALG] [--encrypt] [--pubout FILE]` | A new private key, and its public key if asked. |
| `req --key KEY --subject DN [--san NAME]... [--out FILE]` | A certificate signing request, signed by the key it is for. |
| `selfsign --key KEY --subject DN [--profile ca] [--days N]` | A certificate signed by the key it certifies: a root, or a lone server's. |
| `sign --csr REQ --ca CERT --ca-key KEY [--profile server] [--bundle]` | A certificate for a request whose signature verifies. `--subject` and `--san` replace the request's. `--bundle` writes the issuer's chain (the rest of `--ca`'s file) after the new certificate, as a server presents it. |
| `verify CERT [--ca ROOT]... [--untrusted CERT]... [--crl CRL]...` | See [Verifying](#verifying). |
| `show FILE... [--json]` | Describes each certificate, request, revocation list or key, like `openssl x509 -text`. A private key is shown by its public half alone, and an encrypted one by its encryption. |
| `convert IN --out FILE [--to pem\|der] [--encrypt \| --decrypt] [--pubout FILE]` | Re-encodes, encrypts, decrypts, or extracts a public key. A key goes through the parser on the way, so it comes out as the PKCS#8 this writes. |
| `match A B` | Whether two files hold the same key, such as a key and its certificate. Each may be a key, a certificate, a request or a public key. |
| `fingerprint FILE... [--alg sha256] [--spki]` | A digest: SHA-256, -384 or -512, or SHA3-256, -384 or -512. `--spki` takes the public key's, the form a pin takes. A key's fingerprint is always its public key's. There is no SHA-1 or MD5. |
| `crl --ca CERT --ca-key KEY [--revoke SERIAL[:REASON]]... [--from CRL]` | See [Revocation lists](#revocation-lists). |
| `ca init\|issue\|revoke\|list\|crl DIR ...` | See [A managed CA](#a-managed-ca). |
| `probe HOST[:PORT] [--ca ROOT]... [--groups pq] [--require-pq]` | See [Probing a server](#probing-a-server). |
| `serve --cert CHAIN --key KEY [--listen ADDR] [--client-ca ROOT]...` | See [Serving](#serving). |

Flags and arguments go in any order. Everything that writes takes `--out` (`-` is stdout,
where the commands that make a public object default to), `--der`, and `--force`. Status lines
go to stderr, so stdout is only ever what was asked for. `conflux cert COMMAND -h` lists a
command's flags.

## Verifying

`verify` builds a chain from `CERT` to a trusted root and checks it:

- **Roots.** These come from `--ca`, repeated. With none, the system's roots are used; on macOS
  and Windows the operating system's verifier then checks the chain, and it usually cannot
  verify ML-DSA, so use `--ca` there.
- **Intermediates.** Every certificate after the first in `CERT`'s file, and `--untrusted`'s.
  They are trusted for nothing.
- **What is checked:** validity at `--at` (RFC 3339 or a date; now by default), `--purpose`
  (`server`, `client` or `any`, against the chain's extended key usages), and `--name`, a host
  or an address.
- **Revocation lists.** Each certificate below the root is checked against its issuer's list,
  where one was given with `--crl`. A list is its issuer's when its issuer name matches and its
  signature verifies; a list from no issuer in the chain is noted and not used. A revoked
  certificate fails the check, naming the reason. So does a list out of date: a list past its
  next update says nothing about now.
- **Authentication.** Reported as `pqc` when the leaf's key and every signature below the root
  are ML-DSA: nothing in the chain could be forged by a quantum computer. One classical link
  makes it `classical`. `--require-pq` fails a chain that is not `pqc`.

`--json` gives the same answer as an object. The exit code is 0 when the certificate is
valid, and 3 when it is not.

## A managed CA

`conflux cert ca` keeps a certificate authority in a directory: a root, optionally an issuing
CA beneath it, every certificate they issued, what they revoked, and their CRLs. The commands
above do the same things one file at a time; this is for a CA that has to remember.

```sh
conflux cert ca init ./ca --name Example --intermediate --crl-url http://ca.example/crl.pem
conflux cert ca issue ./ca --csr server.csr --bundle --out server.pem
conflux cert ca list ./ca
conflux cert ca revoke ./ca 41:24:71:…:AB --reason keyCompromise
conflux cert ca crl ./ca                   # publish again before the last list's next update
```

| Command | |
|---|---|
| `init DIR --name NAME [--org ORG] [--alg ALG] [--intermediate [--intermediate-alg ALG]]` | Makes the CA in a new or empty directory. The root is `NAME Root CA` (ML-DSA-87, 3650 days by default). With `--intermediate`, `NAME Issuing CA` (ML-DSA-65, 1825 days) is made under it, so the root's key can then be kept offline. Its keys are encrypted under a passphrase unless `--no-encrypt`. `--leaf-days`, `--crl-days` and `--crl-url` set what it issues and publishes. |
| `issue DIR --csr REQ [--profile server] [--days N] [--san NAME]... [--bundle]` | Issues an end-entity certificate for a request: `server`, `client` or `server+client`, never another CA. It is recorded before it is written out. `--bundle` writes the intermediate after it, the chain a server presents. |
| `revoke DIR SERIAL [--reason REASON]` | Revokes a certificate this CA issued, and publishes its CRL. A serial it never issued, or one already revoked, is refused. |
| `list DIR [--json]` | Every certificate issued, soonest to expire first: valid, expired, or revoked and why. |
| `crl DIR` | Publishes the CRLs again, numbered on. A CRL is valid for `--crl-days`, so this is what a schedule runs. |

The directory:

| File | |
|---|---|
| `ca.json` | the settings `init` was given |
| `root.pem`, `root.key` | the root, and its key |
| `intermediate.pem`, `intermediate.key` | the issuing CA, with `--intermediate` |
| `chain.pem` | the issuing CA and the root, issuer first |
| `issued/SERIAL.pem` | one file per certificate issued: the CA's record of what it issued |
| `index.json` | what was revoked, and the last CRL numbers used |
| `crl.pem`, `root.crl` | the issuing CA's CRL, and with an intermediate the root's |
| `.lock` | held by whichever command is working in the CA; a second one is refused |

- **The directory is guarded.** It is made 0700 (its creator's alone on Windows). It is refused
  if another account owns it, or, on Unix, if others may write it, since whoever can write it can
  replace the CA.
- **Nothing is lost to a crash.**
  - A certificate is written to `issued/` under its serial before it is handed out, and only
    where no certificate of that serial is. What `issued/` holds is what was issued, and a serial
    is never issued twice.
  - A CRL's number is recorded in `index.json` before the CRL is written, so a crash between
    the two skips a number rather than using one twice.
- **No subscriber's key is in it.** A certificate is issued for a request, whose key stays with
  whoever made it.
- **Path lengths.** The root's path length is 1 with an intermediate and 0 without; the
  intermediate's is 0. Nothing below the CA can issue.
- **Revocation is final.** There is no `certificateHold`. Revoking the issuing CA itself is not
  offered: make a new CA.

## Probing a server

`probe` connects as a FIPS 140-3 mode TLS client, like `openssl s_client`, completes the
handshake, sends nothing else, and says what was negotiated:

```
$ conflux cert probe server.example:8443 --ca root.pem --require-pq
Connected to server.example:8443 (192.0.2.10:8443), as server.example
  tls             TLS 1.3, TLS_AES_128_GCM_SHA256
  key exchange    SecP384r1MLKEM1024 (hybrid)
  signature       ML-DSA-65 (pqc)
  chain           verified for server.example, authentication pqc
    leaf          CN=server.example: ML-DSA-65 key, signed ML-DSA-87
    root          CN=Example Root,O=Example: ML-DSA-87 key, signed ML-DSA-87
  post-quantum    key exchange yes; authentication yes
```

- **Key exchange.** This is the group the server picked. It is `hybrid` for ML-KEM beside a
  classical group (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024), `pqc` for
  ML-KEM-1024 alone, and `classical` for P-256, P-384 and P-521: the observer's words.
  `--groups` limits what is offered: `pq`, `classical`, or names. crypto/tls orders the offer
  itself, and the server picks by its own order. X25519 is never offered alone; FIPS 140-3 does
  not approve it, and X25519MLKEM768 carries it.
- **Signature.** crypto/tls does not report the handshake's signature scheme, so it is inferred
  from the leaf's key. That is exact for ML-DSA, for Ed25519, and for ECDSA in TLS 1.3, which
  binds the curve to its hash. For RSA, and ECDSA in 1.2, the padding and hash are the peers'
  choice and are not said.
- **Chain.** The chain is checked as `verify` checks it, for `--name` (the host by default),
  against `--ca` or the system's roots. One that does not verify is described rather than only
  refused, along with the class of what was presented.
- **Requirements.** `--require-pq-kex` fails a classical key exchange. `--require-pq-auth`
  fails unless the chain verifies and is ML-DSA throughout. `--require-pq` asks for both.
- **Options.** `--tls 1.2|1.3`, `--alpn`, `--cert`/`--key` for a client certificate,
  `--timeout`, and `--json`.

The exit code is 0, or 3 when the chain does not verify or a requirement is not met, or 1 when
there was no handshake. A FIPS 140-3 mode client offers TLS 1.2 and 1.3, AES-GCM (and, in 1.2,
AES-CBC with SHA-256), the groups above, and ML-DSA, ECDSA, RSA-PSS, RSA PKCS #1 v1.5 and
Ed25519 signatures. A server that accepts none of them fails the handshake, and the error says
so.

## Serving

`serve` answers TLS as a FIPS 140-3 mode server, like `openssl s_server`. For each client it
reports what the client offered (its SNI, versions, groups, signature schemes and ALPN) and
what was negotiated. A client that sends an HTTP request is answered with the same report as
`text/plain`, so `curl` and a browser show it; anything else is sent the report and closed.

```sh
conflux cert serve --cert chain.pem --key server.key --listen :8443
openssl s_client -connect localhost:8443 -groups SecP384r1MLKEM1024 -CAfile root.pem
```

- **Listening.** `--listen` defaults to 127.0.0.1:8443.
- **Client certificates.** `--client-ca` requires one from every client, verified against that
  root, and the report names its subject.
- **Groups and ALPN.** `--groups` limits the groups. `--alpn` sets what is advertised;
  `http/1.1` when not given.
- **Output.** `--once` stops after the first client, exiting 1 if its handshake failed.
  `--json` reports each client as a line of JSON.
- **Stopping.** Ctrl-C stops it.

## Revocation lists

`crl` makes the list an issuer publishes:

- **Entries.** Each `--revoke` takes a serial in hex, colons or not, and optionally a reason:
  `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`,
  `cessationOfOperation`, `privilegeWithdrawn` or `aACompromise`. `certificateHold` is not
  offered: a revocation here is final.
- **`--from`** carries the entries of the issuer's last list into the new one, numbered one
  after it, so a list can grow without a database. The old list must verify as the issuer's.
- **Numbering.** `--number` sets the number; without it, or a `--from`, the number is the time
  in seconds, which only grows.
- **Next update.** It is due again in `--days`, 7 by default.

## Checked against OpenSSL

OpenSSL 3.5 is the first that reads ML-DSA. These were checked against OpenSSL 3.5.9:

- **OpenSSL reads conflux's output.**
  - `openssl x509 -text`, `req -verify`, `crl -text` and `pkey -text` read it;
  - `openssl verify` accepts an ML-DSA-87 → ML-DSA-65 → ML-DSA-65 chain, with `-purpose
    sslserver -verify_hostname`, and finds the same leaf revoked under `-crl_check_all` that
    `conflux cert verify` does;
  - `openssl pkey` opens an encrypted key, and `openssl pkcs8` opens the PBES2 known answer in
    the tests to the same bytes.
- **conflux reads OpenSSL's.**
  - Its default ML-DSA key (the seed and the expanded key) is read, matches its certificate,
    and converts to the seed form;
  - its PBES2 key decrypts;
  - its request is signed, and `openssl verify` accepts the result;
  - its PBES1, scrypt, `priv-only` ML-DSA and legacy-PEM keys are refused, each by name.
- **A managed CA.** `openssl verify -crl_check_all` accepts a `cert ca` chain (root, intermediate
  with `pathlen:0`, leaf) and both of its CRLs, and finds the leaf revoked once `ca revoke` has
  published.
- **TLS, both ways.**
  - `openssl s_client -groups SecP384r1MLKEM1024` against `conflux cert serve` negotiates TLS
    1.3, SecP384r1MLKEM1024 and `mldsa65` (the scheme `probe` and `serve` infer), and
    verifies the ML-DSA chain;
  - `conflux cert probe` against `openssl s_server` with an ML-DSA-87 certificate verifies it
    over SecP256r1MLKEM768, and over ML-KEM-1024 alone.

Most browsers, curl, and TLS stacks built on older OpenSSL cannot use an ML-DSA certificate
yet. For a server those clients must reach, issue an ECDSA leaf (under an ML-DSA root, if you
like): classical, but widely accepted.

## What `conflux cert` does not do

PKCS#12, in its common form, is not approved: SHA-1, 3DES, RC2 and PKCS#12's own KDF. SLH-DSA
is not offered either. Nor are OCSP, ACME, Certificate Transparency, SHA-1 fingerprints, and
probing STARTTLS or QUIC.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | done, or the check held |
| 1 | failure: a file unreadable, a key refused, a passphrase wrong |
| 2 | usage |
| 3 | a check that ran and did not hold: `verify` found the certificate not valid, `match` found two keys, `probe` found a chain that does not verify or a requirement not met |
| 70 | this conflux does not run in FIPS 140-3 mode, so it makes and checks nothing |
