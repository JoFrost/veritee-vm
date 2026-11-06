# TLS Channel Binding for the Veritee TEE: Problem & Design Options

**Status:** Draft for discussion (revised per PR #13 review; extended with the normative
key-exchange protocol §6 and threat model §7; **§6.1 two-tier attested-epoch-key is the
plan of record and matches the implemented `akx` crate** — see issue #15)
**Audience:** Veritee VM / Warden / browser-extension contributors
**Scope:** How a client (in particular a Chromium browser extension) can establish a
trusted, confidential channel to a service running inside the attested Veritee TEE.

---

## 1. Context

The Veritee VM is an Azure Confidential VM (AMD SEV-SNP) that attests itself using a
SEV-SNP hardware report plus an Azure vTPM quote. The client verifies this attestation
before trusting anything the VM says.

Attestation on its own only proves *"some genuine, correctly-measured TEE exists"*. It
does **not**, by itself, prove that *"the specific network connection I am using
terminates inside that TEE."* Closing that gap is called **channel binding**: tying the
transport the client actually uses to the enclave it actually attested.

Without channel binding, a man-in-the-middle (MITM) can relay a valid attestation from a
real TEE while terminating the client's connection at attacker-controlled infrastructure
(a "relay" / "cuckoo" attack). The client believes it is talking to the enclave; it is
not.

### The endpoints involved

| Endpoint | Transport | Purpose |
| --- | --- | --- |
| `https://attestation-endpoint.../tee_attestation` | TLS (Caddy) | Live attestation evidence (MAA JWT or raw SEV-SNP) + TPM quote |
| `https://attestation-endpoint.../attestation.json` | TLS (Caddy) | Static pre-generated attestation bundle |
| `https://api.mydapp.../` | TLS (Caddy) | The DApp API, reverse-proxied by Caddy |
| `/prove` (extension flow) | TLS | The request whose channel we need to trust |

> **Note.** The `/prove` endpoint and the Chromium extension client are not part of this
> repository; they live in the Warden / extension project. This document records the
> design decision so the reasoning is preserved outside of Slack.

---

## 2. The current design: SPKI binding

The current (planned) approach binds the TLS certificate's public key to the
attestation:

1. The VM serves TLS with a certificate whose key it controls. For browser clients this
   must be a **browser-trusted certificate mounted at runtime** — currently provisioned via
   **Azure Key Vault + managed identity** (e.g. a Let's Encrypt–issued cert, though the
   mechanism is not Let's Encrypt-specific). Note, however, that a browser-trusted cert is
   *not* required for the binding itself (see §8): because trust is derived from
   attestation, a **self-signed certificate generated inside the TEE** also works for
   non-browser clients that can pin it.
2. The **SPKI** (`SubjectPublicKeyInfo` — the ASN.1 structure that encodes the public key
   together with its algorithm identifier; pinning normally compares a cryptographic
   *hash* of this structure) is committed to the attestation. In this repo it is measured
   into **PCR15** and surfaced via the attestation document (`attestation.json`), so the
   attestation commits to the expected serving key.
3. The client performs four steps:
   - **(a) read expected:** read the attested SPKI from `attestation.json`,
   - **(b) connect:** open a TLS connection to `/prove`,
   - **(c) extract presented:** extract the SPKI from the certificate the server
     actually presented,
   - **(d) compare:** compare the presented SPKI against the attested SPKI.

If the two match, the TLS session provably terminates at a party holding the attested
key — i.e. inside the enclave. This is a clean, standard form of channel binding, and it
lets us reuse TLS for confidentiality, integrity, forward secrecy, ordering and replay
protection.

**The entire scheme depends on the extract-presented step (3c) — the client being able to
read the certificate the server presented.**

---

## 3. The problem: a stock Chromium extension cannot read the peer certificate

In a **stock, default-configured Chromium Manifest V3 (MV3) extension**, JavaScript has
**no usable API to obtain the peer TLS certificate**:

- There is no equivalent of Firefox's `browser.webRequest.getSecurityInfo()` enabled by
  default.
- MV3 removed blocking `webRequest`, and extensions have no raw socket / TCP access.

Therefore the extract-presented step (3c) is not achievable in a stock, default-configured
Chromium extension: the presented SPKI cannot be extracted, so it cannot be compared
against the attested SPKI.

**Important scoping:** this limitation is specific to *stock, default-configured Chromium
MV3 extensions* — it does **not** invalidate the SPKI-binding mechanism itself. Because the
SPKI is committed into PCR15, the same design remains valid for:

- **Firefox** extensions (`getSecurityInfo()`),
- **native / non-browser clients** (full TLS stack access),
- **Isolated Web App (IWA) Controlled Frames** (separate certificate API),
- **controlled / enterprise Chromium** deployments (policy or flag enabled),
- **Chrome 144+** with the flag enabled (see below),
- and, plausibly, **future default Chromium** once the feature ships enabled.

### Consequence

If the target client is a stock Chromium MV3 extension that cannot read the presented
cert, then *for that client* the SPKI comparison cannot run, and something else must
provide channel binding (see §4). Two things are worth separating here:

- **The SPKI-binding mechanism** (commit the serving key's SPKI into PCR15, client pins
  it against attestation) — this stays valid and is used by all the capable clients listed
  above.
- **Runtime provisioning of a browser-trusted certificate** (today via Azure Key Vault +
  managed identity; not Let's Encrypt-specific) — this is a *separate* question from the
  binding mechanism. Since trust is derived from attestation, a TEE-generated self-signed
  certificate is sufficient for the *security* binding. **But note an important functional
  constraint for browser clients:** a stock browser (and therefore a stock extension)
  enforces TLS certificate validation on the connection itself and will **refuse to
  connect** to a self-signed certificate. Because the attested secure proxy (§4) runs
  *over* that TLS transport, the connection must succeed *before* any application-layer
  binding can happen. So for browser clients a browser-trusted certificate is a
  **functional requirement to establish the transport at all**, not merely a UX nicety.
  For native / non-browser clients there is no such constraint — they can pin a self-signed
  cert directly. See §8 and §9.

### On `chrome.webRequest.onHeadersReceived` (recent Chrome support)

Chromium **has** shipped an API for this, though not yet enabled for ordinary users:

- **Chrome 144+**: a regular MV3 extension can obtain the TLS certificate via
  `chrome.webRequest.onHeadersReceived` by including `"securityInfo"` /
  `"securityInfoRawDer"` in `extraInfoSpec`; the resulting `SecurityInfo` includes the raw
  DER certificate (`rawDER`). This is documented in the current Chrome `webRequest`
  reference (`SecurityInfo` is marked "Chrome 144+").
- **However, it is disabled by default** and currently gated behind
  `chrome://flags/#web-request-security-info`. A consumer extension cannot ask end-users
  to flip a flag, so this is **not usable for stock end-users today** — but it is usable in
  controlled / enterprise deployments and signals the likely direction for default Chrome.
- **Isolated Web App (IWA) Controlled Frames** expose a separate equivalent certificate
  API.

**Net:** the earlier assumption that this was merely an unshipped proposal is outdated.
The feature exists; the open question is only *when* it becomes available by default. Until
then, we design for the lowest-common-denominator client (stock MV3, flag off) and treat
SPKI comparison as an optimization available to capable clients.

---

## 4. The alternative: application-layer channel binding ("attested secure proxy")

If the transport cannot be authenticated by the client, **treat TLS as an untrusted dumb
pipe** and move the trust to the application layer:

1. The client opens a session with the attestation server.
2. The server generates an **ephemeral asymmetric keypair inside the TEE** and **binds the
   public key to the attestation payload** (it is hashed into `report_data`, so the public
   key is provably produced by the attested enclave).
3. The client verifies the TEE attestation. This authenticates the enclave's **public**
   key. The client then generates its own ephemeral keypair, sends its ephemeral public
   key, and both sides derive the symmetric AEAD key via **ECDH + a KDF (HKDF)**. The
   symmetric key is never transmitted.
4. The client uses the derived symmetric key to **encrypt its request** (e.g. `/prove`)
   sent *through* the attestation endpoint.
5. The server **decrypts the request inside the VM**, forwards the plaintext to the DApp
   **locally** (it never leaves the enclave in the clear), then **encrypts the response**
   back to the client.

> **Recommended instantiation: ephemeral ECDH (equivalently, HPKE / RFC 9180).** Both
> sides use ephemeral keys, so the design gets **forward secrecy** for free, and the
> symmetric AEAD key is *derived*, never sent. HPKE is simply the standardised packaging of
> this "encrypt to an attested public key + derive a session key" pattern and is the
> suggested building block. **This is the plan of record for the doc.**
>
> **Why not the simpler alternatives?**
> - *TEE generates the symmetric key and sends it:* insecure — at this step the channel is
>   still untrusted (that is the whole premise), so a MITM would read the key. A symmetric
>   key can never travel over the untrusted channel.
> - *Plain public-key wrap (client generates the AEAD key and encrypts it to the enclave's
>   attested static public key):* secure and simpler than ECDH, but gives **no forward
>   secrecy** if the enclave key later leaks. Acceptable as a fallback, not the default.
>
> (Credit: the symmetric-delivery flaw and the ECDH-vs-wrap ambiguity were both raised by
> Stefan in PR review.)

The attestation endpoint effectively becomes an **encrypting reverse proxy** in front of
the DApp. Security no longer depends on reading the TLS certificate; it depends only on
the attested (asymmetric) enclave key. This works identically in Chrome, Firefox, or any
client.

A first version of this "attested secure proxy" has been prototyped for the demo.

> **See §6 for the precise, normative handshake** — including the message ordering and
> transcript binding required to resist the interposition attacks catalogued in §7. The
> high-level five steps above are deliberately simplified and omit the transcript binding.

### What TLS gave us, and how to recover it at the application layer

Dropping trust in TLS means we must consciously re-provide the properties we relied on:

| Property | Provided by TLS | How to provide at app layer |
| --- | --- | --- |
| Confidentiality | Yes | AEAD (AES-GCM / ChaCha20-Poly1305) under the session key |
| Integrity / tamper-evidence | Yes | Same AEAD (authentication tag) |
| Replay protection | Yes | Fresh per-session nonce bound into the attestation `report_data`; per-message monotonic counter in the AEAD associated data |
| Message ordering | Yes | Monotonic sequence number in AEAD associated data |
| Forward secrecy | Yes | Ephemeral key agreement (e.g. ECDH) where the **client** also contributes entropy, rather than a static server-minted key |

TLS is still fine to keep underneath (it costs little and provides defense in depth), but
the security argument must **not** rely on it.

> **The dumb pipe must still be a *working* pipe.** "Untrusted" here means we place no
> *security* trust in TLS — it does not mean the transport can fail to establish. For
> browser clients the browser still enforces certificate validation on the connection, so
> the underlying TLS endpoint must present a **browser-trusted** certificate or the request
> never reaches the proxy. Treating TLS as untrusted therefore does **not** let us drop the
> browser-trusted certificate for browser clients (see §3 and §8).

---

## 5. Security requirements for the application-layer approach

These are the properties the design must satisfy, and the questions to scrutinise in any
implementation:

1. **Key origin.** The enclave must publish an **asymmetric** key whose *private* part is
   generated and never leaves the TEE. The symmetric AEAD key must **not** be generated by
   the TEE and shipped to the client over the untrusted channel — it is either generated
   client-side and encapsulated to the enclave's public key, or derived via ECDH. Only the
   enclave's public key is ever transmitted, and only inside the attestation.

2. **Key-to-attestation binding.** The enclave's **public** key (or its hash) must be
   included in the attestation `report_data` (or the MAA payload), so the client's
   verification of the attestation *is* the verification of that public key. The raw
   SEV-SNP mode already hashes `nonce` + `payload` into `report_data`, which is the natural
   anchor for binding the public key.

3. **Client-side freshness.** The client must supply a fresh nonce that ends up in the
   attested `report_data`, so an attacker cannot replay an old attestation + key pair.

4. **Forward secrecy.** Prefer ephemeral key agreement with client-contributed entropy
   over a static, server-chosen session key, to limit the blast radius of key compromise.

5. **AEAD everywhere.** All request/response payloads use an AEAD with a monotonic
   sequence number in the associated data, recovering ordering and per-message replay
   protection.

6. **Enclave-local forwarding.** Decryption and DApp forwarding happen entirely inside
   the VM; plaintext never crosses a network boundary.

7. **Transcript binding & ordering.** The client must send its ephemeral public key and a
   fresh nonce *before* the enclave mints the attestation, and the enclave must bind the
   full handshake transcript — client nonce, client ephemeral public key, and enclave
   ephemeral public key — into `report_data`. This makes each attestation session-specific
   and defeats unknown-key-share / session-splicing. See §6 (protocol) and §7 (attack A3).
   In the implemented **two-tier** variant (§6.1) this per-session binding is realised by an
   *epoch-key signature* over the transcript rather than by a fresh `report_data` each
   session; the attestation instead commits, once, to the enclave's medium-lived signing key.

---

## 6. The attested key-exchange protocol (normative)

This section makes the §4 sketch precise. It is an *attested, ephemeral Diffie–Hellman key
exchange*: standard ephemeral ECDH where the enclave's ephemeral public key is authenticated
by the SEV-SNP attestation, and the whole handshake transcript is bound into the attestation
so the channel is tied to one specific client and session.

> **Plan of record.** The handshake in §6 steps 1–5 below is the *pedagogical* (per-session
> attestation) form. The **deployed** protocol is the **two-tier** variant in **§6.1**: one
> attested medium-lived epoch signing key + per-session HPKE authenticated by an epoch
> signature. Implement against §6.1 (`server/akx/`, `cli/veritee/attested_channel.py`).

### Notation

- `G` — an agreed group / curve (e.g. X25519, or NIST P-256).
- `(s, S = sG)` — the **enclave** ephemeral keypair, generated *inside the TEE* per session;
  `s` never leaves the enclave.
- `(c, C = cG)` — the **client** ephemeral keypair, generated per session.
- `nonce_c` — a fresh random client nonce; `sid` — a session identifier.
- `H` — a collision-resistant hash (SHA-256); `"temenos-akx-v1"` — a protocol/version
  domain-separation label.
- `AEAD` — AES-256-GCM or ChaCha20-Poly1305.
- `Att(x)` — a SEV-SNP attestation (plus vTPM quote) whose `report_data` field equals `x`,
  verifiable against the AMD/Azure roots **and** the expected measurement/policy.

### Handshake (client sends first, so the enclave can bind the transcript)

1. **Client → Enclave** — `ClientHello = { sid, nonce_c, C }`.
2. **Inside the TEE** — generate `(s, S)` and compute

   ```
   report_data = H( "temenos-akx-v1" ‖ sid ‖ nonce_c ‖ C ‖ S )
   ```

   then produce `Att(report_data)`.
   **Enclave → Client** — `ServerHello = { S, Att(report_data) }`.
3. **Client verifies** (and aborts on any failure):
   - the attestation is valid and comes from a genuine SEV-SNP TEE with the **expected
     measurement/policy** and an acceptable **TCB / SVN** (not merely "some TEE");
   - `report_data` equals `H("temenos-akx-v1" ‖ sid ‖ nonce_c ‖ C ‖ S)`, recomputed from the
     client's *own* `sid, nonce_c, C` and the received `S`.

   Passing both proves `S` was generated by the attested enclave **for this specific client
   key `C` and this specific session** — not a replayed or spliced attestation.
4. **Both sides** compute the ECDH secret `Z = cS = sC` and derive directional keys:

   ```
   (k_c2s, k_s2c) = HKDF( Z, salt = nonce_c,
                          info = "temenos-akx-v1" ‖ sid ‖ C ‖ S )
   ```
5. **Record layer** — every message is
   `AEAD_encrypt(k_dir, nonce = dir ‖ 0³ ‖ seq, aad = sid, plaintext)`
   with a strictly monotonic per-direction counter `seq` (`dir` ∈ {c2s, s2c}). The
   implementation carries `dir‖seq` in the **96-bit GCM nonce** (uniqueness / anti-replay);
   AAD is `sid` only (rebinding protection). An earlier sketch put `dir‖seq` in AAD as well;
   that is equivalent for integrity but is **not** what shipped. The enclave decrypts inside
   the VM, forwards plaintext to the DApp over loopback, and encrypts the response under
   `k_s2c`. A typed authenticated close record is **deferred**; for the request/response
   `/proxy` shape, a truncated conversation fails on the next expected record.

### Relationship to HPKE

This is essentially **HPKE (RFC 9180)** with the enclave's key as the recipient key and the
handshake transcript fed into the `info` parameter, plus the attestation covering that
transcript. It can be implemented directly on top of an HPKE library rather than hand-rolling
ECDH + HKDF + AEAD.

### 6.1 Deployment variant: attested epoch key + per-session signed DH (plan of record)

The handshake above mints a **fresh attestation per session**, because `report_data` commits
to the per-session values `nonce_c`, `C` and `S`. That is the simplest model to reason about,
but SNP report + vTPM quote generation costs ~3 s, so paying it on *every* session is
expensive and — by construction — uncacheable. This conflicts with the latency goal of using
a cached / periodically-polled attestation.

The **implemented** design therefore uses a **two-tier** key hierarchy that preserves the
same security properties while making the attestation cacheable / pollable:

1. **Epoch tier (attested once, cacheable).** The enclave generates a medium-lived
   **Ed25519 signing key** `K_e = (sk_e, pk_e)` (rotated per boot / interval) and produces a
   *single* attestation binding its public key:

   ```
   report_data = H( "temenos-akx-v1" ‖ epoch ‖ pk_e )
   ```

   `sk_e` never leaves the enclave. This attestation is served from `GET /enclave-key` and
   may be refreshed by background polling, amortising the ~3 s cost across many sessions.
   Operationally (Phases 5–6): the enclave mints `K_e` at process start (each boot increments
   a persisted epoch counter); a background task **re-attests** the same `pk_e` on an interval
   (`AKX_ATTEST_REFRESH_SECS`) so `GET /enclave-key` stays fast and evidence stays fresh;
   optional timed **rotation** (`AKX_EPOCH_ROTATE_SECS`) mints a new key and bumps the epoch.

2. **Session tier (per client, no new attestation).** Per session the enclave mints a fresh
   ephemeral HPKE keypair `S` and, instead of re-attesting, *signs the transcript* with the
   epoch key:

   ```
   T   = H( "temenos-akx-v1" ‖ sid ‖ nonce_c ‖ S )
   sig = Sign(sk_e, T)          ServerHello = { S, sig }
   ```

   The client (a) verifies **once** that the cached attestation binds `pk_e` (recomputing
   `report_data`), and (b) verifies `sig` over its *own* recomputed `T`. It then runs HPKE to
   `S` (`info = T`) and exports the directional record keys. The client's ephemeral
   contribution is the **HPKE encapsulated key** (`enc`) rather than a pre-sent `C`; HPKE
   binds it into the derived keys, and the epoch signature over `nonce_c ‖ S` supplies the
   per-session freshness that defeats the A2/A3 replay/splicing attacks.

This is the standard *"attested long-term key + per-session signed ephemeral DH"*
construction — the enclave's attested `pk_e` plays exactly the role of a certificate key in
**RA-TLS**. The properties of §6 are unchanged: **server authentication** (only the enclave
holds `sk_e`, and `S` is signed), **forward secrecy** (`S` and the client ephemeral are
per-session), **freshness / anti-replay** (`nonce_c` is signed into `T`), and **transcript
binding** (the signature ties `S` to this `sid`/`nonce_c`). The only change is *where* the
per-session binding lives: in a signature under an attested key, rather than in a fresh
`report_data` every time. This is the variant implemented in the `akx` crate
(`server/akx/`); the phased plan is tracked in issue #15.

### Properties obtained

Under the pedagogical per-session-attestation handshake (§6 steps 1–5):

- **Server authentication** — only the attested enclave holds `s`, so only it can complete
  the exchange for `S`.
- **Forward secrecy** — `s` and `c` are ephemeral and discarded after the session.
- **Session/transcript binding** — `report_data` commits to `nonce_c`, `C` and `S`, tying
  the attestation to this handshake and client.
- **Record confidentiality, integrity, ordering, anti-replay** — AEAD + monotonic `seq`.

Under the **deployed two-tier** variant (§6.1) the same properties hold, with the binding
locus moved: attestation commits once to `pk_e`; per-session freshness and anti-splicing
come from the epoch signature over `T = H(… ‖ sid ‖ nonce_c ‖ S)` plus HPKE's binding of
`enc` into the record keys. The epoch attestation is refreshed in the background (and may
be polled by clients) so the ~3 s evidence-gathering cost is amortized across sessions.

---

## 7. Threat model and attacks

### Adversary model

Assume a **Dolev–Yao network attacker** with full control of the untrusted transport (it can
read, drop, modify, reorder and replay traffic). Additionally the attacker may **(a)** run its
own malicious client, and **(b)** obtain genuine attestations from the real enclave — the
attested public key is a fetchable, effectively *bearer* value, so possessing a valid
attestation proves nothing about who is presenting it.

**Trust roots (out of scope for attack):** the SEV-SNP hardware and the AMD/Azure attestation
roots; the measured application disk (dm-verity → PCR15) and therefore the DApp binary; a
correctly implemented, fail-closed client verifier.

### Attacks and defenses

**Channel establishment**

- **A1 — Interposition / MITM key substitution (relay, "cuckoo").** An interposer (or
  malicious client holding a valid attestation) tries to sit between the honest client and the
  enclave. *Defense:* the key exchange is anchored to the **attested** `S`; the session key
  requires `s` or `c` (CDH), which the interposer lacks, so it is reduced to an unreadable
  relay. Substituting its own key for `S` fails the attestation check in §6 step 3.
- **A2 — Attestation replay / staleness.** Presenting a genuine but old attestation (possibly
  from a since-patched or rolled-back enclave). *Defense (pedagogical §6):* the fresh
  `nonce_c` is bound into `report_data`; the client rejects any attestation not bound to its
  current nonce. *Defense (deployed §6.1):* `nonce_c` is bound into the **epoch-signed
  transcript** (so a stale *session* handshake fails); the epoch attestation itself is
  refreshed on a timer and should be checked against an acceptable TCB/SVN freshness policy
  by Warden. Epoch **rotation** (new `pk_e`) limits the window if `sk_e` is compromised.
- **A3 — Unknown key-share / session splicing.** A faithful relay so that client and enclave
  share a key but disagree about the peer/identity. *Defense:* bind `C` (and any client
  identity) into `report_data`; client-first ordering (§6). This is the correction over the
  simplified §4 sketch.
- **A7 — Algorithm / mode downgrade.** Forcing the insecure "TEE generates and sends the
  symmetric key" fallback, the no-forward-secrecy static-wrap mode, or a weak cipher.
  *Defense:* do not offer the symmetric-delivery mode at all; pin a single ciphersuite, or
  bind all negotiated parameters into the transcript hash so a downgrade is detected.
- **A12 — Weak randomness.** Predictable ephemeral `c`/`s` or nonces collapses ECDH/AEAD.
  *Defense:* a vetted CSPRNG seeded from hardware entropy (RDRAND/RDSEED inside the CVM;
  `crypto.getRandomValues` on the client); never reuse ephemerals.

**Record layer**

- **A4 — AEAD nonce/IV reuse.** Catastrophic for GCM (breaks confidentiality *and* enables
  forgery). *Defense:* deterministic per-direction counter nonces that are never reused under a
  key; separate keys per direction; rekey / new session well before the counter can wrap.
- **A5 — Record replay, reordering, truncation.** *Defense:* monotonic `seq` in the GCM
  nonce (`dir‖seq`), AEAD integrity over AAD=`sid`, and dropping the session on any open
  failure. A typed authenticated close is deferred for the `/proxy` request/response shape.

**Attestation & platform**

- **A6 — Attestation rollback / TCB (SVN) downgrade.** A genuine attestation from older,
  vulnerable firmware/microcode. *Defense:* verify the SEV-SNP TCB and reported SVNs (and
  bootloader/microcode versions) against a **minimum policy**; reject known-vulnerable
  measurements. Ties to `policy.json` / `pcrs.json`.
- **A9 — Compromised or unexpected DApp behind the proxy.** The proxy decrypts inside the VM
  and forwards plaintext locally; if the running DApp is not the one that was attested, the
  plaintext is exposed to attacker-controlled code. *Defense:* the app disk is measured
  (dm-verity → PCR15) and covered by attestation; the client policy must require the
  **expected app measurement**, not merely "a genuine TEE".
- **A11 — Side channels & traffic analysis.** SEV-SNP does not eliminate timing/cache side
  channels, and even encrypted traffic leaks sizes/timing. *Defense:* constant-time crypto and
  no secret-dependent branching in the proxy; consider length padding / traffic shaping for
  sensitive flows.

**Operational**

- **A8 — Denial of service via setup cost.** Attestation generation (SNP report + quote) and
  asymmetric operations are expensive; an attacker floods session setups. *Defense:*
  rate-limit, require a cheap client cookie / proof-of-work before minting an attestation, and
  cache where safe.
- **A10 — Proxy forwarding abuse (SSRF / target confusion).** Inducing the decrypting proxy to
  forward to an unintended destination. *Defense:* keep the upstream origin fixed by
  configuration (for example `DAPP_UPSTREAM_URL` on loopback), allow only validated relative
  paths when HTTP tunnelling is enabled, reject path traversal / absolute destinations, support
  route allowlists, and egress-restrict the proxy.
- **A13 — No client authentication / authorization.** The channel authenticates the *server*,
  not the client, so a malicious client can legitimately open sessions and call `/prove`. This
  is only an issue if `/prove` requires authorization. *Defense:* layer explicit client
  authentication on top if needed — **channel binding ≠ client auth**.
- **A14 — Client-side verification bypass.** The strongest crypto fails if the client skips
  attestation verification, tolerates a measurement/policy mismatch, or trusts on first use.
  *Defense:* mandatory, fail-closed verification; a tested verifier; pinned expected
  measurement/policy; no TOFU.
- **A15 — Key material lifetime / memory hygiene.** Ephemeral private keys and session keys
  lingering in memory. SEV-SNP protects guest memory from the host, but in-guest bugs still
  apply. *Defense:* zeroize ephemeral secrets promptly; bound session lifetime; re-attest /
  rekey periodically (see §9).

---

## 8. Recommendation

The two approaches are **complementary, not mutually exclusive.** Keep the SPKI→PCR15
binding as the channel-binding mechanism wherever the client can use it, and use the
attested secure proxy to provide channel binding for clients that cannot read the presented
certificate. **The TLS certificate mode is a per-dApp choice** — recommend the strongest
option each client can actually use.

**Two certificate modes, chosen per client:**

- **TEE-generated self-signed certificate (preferred whenever supported).** The cert is
  generated inside the enclave and its SPKI is committed via PCR15; the client pins the
  attested SPKI directly. This keeps the trust root **entirely inside the attested
  environment** with **no dependency on non-TEE Azure components**, which is the best fit
  for Veritee's trustless positioning. This is the recommended default for
  **non-web-browser clients** (e.g. the Charles zk prover, Midnight City, Confidential
  Agents), which can pin a self-signed cert and have no need for a publicly-trusted one.
- **Mounted browser-trusted certificate (required for browser clients).** A stock browser
  refuses to connect to a self-signed certificate, so a browser-trusted cert is a
  **functional requirement** for web-extension clients — the connection (and therefore the
  attested secure proxy that rides on it) fails without one. This is **not** merely a UX
  concern, and it is **not Let's Encrypt-specific**: it is about provisioning a
  browser-trusted certificate at runtime, for which **Azure Key Vault + managed identity is
  currently the only practical mechanism** we have. This mode was implemented for a
  concrete, present need (the Chromium extension POC could not communicate with the VM over
  the internal self-signed TLS), so it is not a speculative / YAGNI feature.

**Recommendation:**

- For the **demo (near term):** adopt the **attested secure proxy** (Section 4) as the
  channel-binding mechanism (it works for stock Chromium MV3 with the flag off), and
  **retain the mounted browser-trusted certificate** as the outer transport — required
  because the browser extension cannot connect over a self-signed cert.
- For **capable clients** (Firefox, native, IWA Controlled Frames, Chrome 144+ with the
  flag, controlled/enterprise Chromium): keep SPKI comparison as an additional, defence-
  in-depth binding. The SPKI→PCR15 commitment stays in the design; it is not retired.
- For **non-web-browser clients:** default to the **TEE-generated self-signed certificate**
  and **do not pull in the Azure Key Vault / managed-identity path** — there is no reason
  to add a non-TEE trust dependency for a client that can pin a self-signed cert.
- **Direction of travel:** we would like to remove the Azure Key Vault dependency for the
  browser case too, moving to a more stateless / TEE-based certificate-provisioning model.
  That is tracked as future work and is **separate** from the per-dApp self-signed-vs-mounted
  choice; we should not build a new provisioning service until a concrete need requires it.

---

## 9. Open questions

- For **web-browser clients**, browser-trusted TLS is a functional requirement (§3, §8)
  and Azure Key Vault + managed identity is currently the only practical runtime mechanism
  to provide it. What would a **stateless / TEE-based** certificate-provisioning model look
  like that removes this non-TEE dependency, and is it worth building yet? (For non-browser
  clients the recommendation is already a TEE-generated self-signed cert — see §8.)
- When is `chrome://flags/#web-request-security-info` expected to become enabled by
  default? Is enabling it acceptable for any controlled/enterprise deployment target?
- Do we require forward secrecy for `/prove`, or is replay + confidentiality + integrity
  sufficient for the threat model?
- §6 fixes the key-exchange as per-session ephemeral ECDH (with transcript binding). What
  should the **session lifetime / re-attestation / rekey cadence** be, and when must a long
  session force a fresh attestation?
- **Ciphersuite (recorded).** The implementation pins **X25519 / HKDF-SHA256 / AES-256-GCM**
  via HPKE (RFC 9180) for the session, **Ed25519** for the epoch signing key, and the
  domain-separation label `"temenos-akx-v1"`. This is fixed in the `akx` crate so client and
  enclave cannot disagree; changing any of it requires bumping the label. (AES-256-GCM is
  chosen over ChaCha20-Poly1305 for WebCrypto portability to the future extension client.)

---

## References

- Chrome `webRequest` reference — `SecurityInfo` / `securityInfoRawDer` on
  `onHeadersReceived` (marked "Chrome 144+"):
  <https://developer.chrome.com/docs/extensions/reference/api/webRequest>
- w3c/webextensions proposal — `WebRequest.securityInfo`:
  <https://github.com/w3c/webextensions/issues/882>
- Google explainer draft — security-info-web-request (Controlled Frame):
  <https://github.com/explainers-by-googlers/security-info-web-request>
- HPKE — Hybrid Public Key Encryption, RFC 9180:
  <https://www.rfc-editor.org/rfc/rfc9180>
- AEAD interface, RFC 5116: <https://www.rfc-editor.org/rfc/rfc5116>
- HKDF, RFC 5869: <https://www.rfc-editor.org/rfc/rfc5869>
- Background on unknown key-share attacks in authenticated key exchange (Blake-Wilson &
  Menezes): <https://link.springer.com/chapter/10.1007/3-540-49162-7_12>
- RA-TLS (attestation-bound TLS), the analogous "bind attestation into the key exchange"
  pattern: <https://arxiv.org/abs/1801.05863>
- In-repo attestation code: `server/azure_attestation_server/src/main.rs`,
  `server/guest_attestation/veritee_attestation/document.py`,
  `cli/veritee/cli.py`
