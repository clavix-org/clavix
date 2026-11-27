# Threat Model

This document describes the security goals and assumptions of Clavix as
it exists today. It is not a proof of security. It is a map for code
review, design discussion, and future hardening work.

## Security Goals

Clavix aims to:

- authenticate to Vaultwarden / Bitwarden-compatible servers without
  sending the master password in clear text
- decrypt and encrypt vault data client-side
- keep sensitive long-lived material encrypted at rest on disk
- auto-lock and drop in-memory session state after inactivity
- support organization items and re-encryption flows without leaking
  plaintext to the server
- expose SSH private keys to local SSH clients without writing those
  private keys to standalone PEM files on disk

## Assets to Protect

Primary assets:

- master password
- derived master key
- user symmetric key
- decrypted organization keys
- decrypted vault items and item metadata
- refresh token and access token
- private SSH keys stored in the vault
- TOTP secrets stored in login items

Secondary assets:

- item names, usernames, URIs, notes, and folder structure
- local cache contents
- session metadata stored on disk
- device identifier used for Vaultwarden auth flows

## Trust Boundaries

Clavix crosses these main boundaries:

1. Svelte frontend to Rust backend via Tauri commands
2. Rust backend to remote Vaultwarden / Bitwarden-compatible HTTP API
3. In-memory decrypted state to persisted local state on disk
4. Clavix process to local OS integrations:
   clipboard, camera, SSH agent socket, WebAuthn HID access

The most security-sensitive boundary is the Tauri IPC surface. The
frontend is trusted application code shipped with the app, but the Rust
side must still treat command inputs as untrusted and validate them
accordingly.

## Attacker Model

Clavix primarily tries to resist:

- a malicious or curious server operator who can observe ciphertext,
  protocol fields, and timing, but should not learn vault plaintext
- a passive attacker reading local storage files such as `session.json`
  or `vault.db`
- an attacker who tampers with encrypted server or cache data and tries
  to trigger unsafe parsing or incorrect decryption
- accidental data loss or inconsistent state during destructive flows
  such as share, move, delete, and folder rename cascades

Clavix does not fully resist:

- a fully compromised local OS user session
- malware running as the same desktop user
- a hostile kernel, debugger, or root account
- physical attacks against a powered-on unlocked machine
- side-channel attacks outside the guarantees of the underlying crypto
  libraries and operating system

## Explicit Assumptions

Current design assumptions include:

- the local machine is under the user's control to a reasonable degree
- disk encryption is recommended for real-world use
- the remote server may be untrusted for confidentiality, but is still
  relied upon for protocol correctness and item storage
- Tauri, the system WebView, RustCrypto crates, and OS APIs are trusted
  dependencies unless a known vulnerability says otherwise
- TLS to the server trusts the bundled webpki roots plus the operating
  system's certificate store (since #451, so private CAs work). Whoever
  can add a root CA to that store can intercept the connection: they
  would see the master password hash, tokens and encrypted vault, not
  plaintext, and could then attack the master password offline. Adding a
  root CA takes root on Linux, and on macOS and Windows at least the
  user's own confirmation in a system prompt; an attacker who can do
  that is the compromised session or same-user malware listed above
- once the vault is unlocked, plaintext necessarily exists in process
  memory and may be exposed by a local compromise

## Sensitive Data Lifecycle

### Authentication and Unlock

- the frontend sends login and unlock requests to Rust commands
- the Rust backend derives the master key from the password and server
  KDF parameters
- the backend authenticates to the server with derived values rather
  than the raw master password
- the user key is recovered from encrypted server material and held in
  memory for the unlocked session

### Persistence

- the session file stores server URL, email, KDF parameters, encrypted
  user key, optional encrypted private key, and an encrypted refresh
  token
- the offline cache stores an encrypted blob keyed by account identity
- Unix builds try to apply restrictive permissions to these files

### Runtime

- decrypted vault contents live in Rust memory while the session is open
- selected item details also flow into frontend state for rendering
- copied secrets enter the system clipboard temporarily
- SSH keys may be loaded into the local Unix-domain SSH agent

## High-Risk Flows

These flows deserve concentrated review:

- key derivation and EncString parsing/decryption
- persisted session unlock using stored encrypted material
- token refresh and migration away from legacy plaintext refresh tokens
- offline cache encryption and decryption
- **standalone (server-less) sessions** — see below
- encrypted export files: KDF floors, header authentication, and the
  re-key walk that must not miss a field
- organization item sharing and cross-org re-encryption
- folder rename batch operations and the (write-only, not yet replayed)
  pre-operation snapshots and op-log entries persisted around them
- SSH agent socket exposure and request handling
- WebAuthn challenge parsing and authenticator interaction
- clipboard handling and auto-lock behavior when the UI freezes

## Standalone Sessions

A vault used to be openable only by authenticating against a reachable
server. There are now two further ways in, both read-only:

- **Offline cache** — the unlock derives the user key locally (it always
  did; the network call only ever fetched an access token) and, when the
  server cannot be reached, opens the encrypted SQLite cache instead of
  failing.
- **Export file** — an encrypted export is opened with its own file
  password. No account, no stored session, no network.

This matters for review because it is a **second, independent path to a
decrypted vault in memory**, and it does not pass through the
assumptions the rest of the auth surface leans on:

- It never contacts a server, so `ensure_server_matches_active_session`
  has no pinned host to compare against. A standalone session therefore
  *refuses* first-factor calls outright rather than treating "no client"
  as "any host is fine".
- A file-backed session has no persisted session on disk behind it, so
  anything reading `store::load_session()` — including the per-item
  master-password reprompt — has nothing to check against.
- The vault key comes from the file, not from the account. Two different
  files opened in sequence are two unrelated vaults.

The write surface is fenced off in Rust, not in the UI: every mutating
command calls `ensure_fresh_tokens`, no read path does, and it refuses
any session with no tokens (`Error::ReadOnlySession`). The hidden
buttons are a courtesy; that check is the control. A review should look
for a mutating command added later that skips it.

Also disabled, for reasons that do not follow from "read-only":

- **attachment download** — payloads live on the server, not in the
  vault, so there is nothing local to decrypt;
- **the security audit** — it queries HIBP over the network;
- **SSH agent auto-start** — it would expose the vault's keys on a
  socket during what is, by definition, an unusual situation.

## Likely Failure Modes

Examples of realistic failures to look for:

- using the wrong key when decrypting or re-encrypting an item
- accepting malformed ciphertext or weakly validating EncString parts
- persisting secrets longer than intended
- command handlers trusting frontend state too much
- leaving secrets behind after lock/logout/crash
- stale or partially-applied move/share operations corrupting data
- insecure file or socket permissions on some platforms
- information disclosure through logs, error serialization, or UI state

## Optional: Yubikey Re-Unlock (planned)

A planned feature lets the user release the in-memory session via a
FIDO2 hardware token (CTAP2 `hmac-secret` extension) instead of
re-typing the master password after auto-lock. The full design lives
in `YUBIKEY_UNLOCK.md`. The threat-model implications below apply
only when a user has explicitly opted in.

What enabling Yubikey re-unlock changes:

- **a new on-disk asset.** The session file gains an encrypted copy
  of the user key, wrapped under a key derived from the
  authenticator's `hmac-secret` output. The wrap key never touches
  disk; only the AES-256-CBC + HMAC-SHA256 ciphertext (Bitwarden
  EncString format, the same primitive already used elsewhere in
  the app), the per-credential salt, the credential id, and a
  non-secret 16-byte HKDF fingerprint of the user key.
- **a shifted at-rest threat.** While the wrap is present, the
  encrypted user key on disk is protected by the Yubikey's secret
  rather than by the master password. An attacker who steals the
  laptop and the Yubikey can unlock the vault — equivalent to
  stealing the master password. An attacker with the laptop alone
  cannot.
- **an extra unlock surface.** Two new Rust commands
  (`enroll_yubikey_unlock`, `unlock_with_yubikey`) talk to the
  authenticator over the existing CTAP-HID stack. The same input
  validation rules as the WebAuthn 2FA path apply.
- **stale-wrap detection.** If the master password is rotated on
  another client, the wrapped user key becomes invalid. The stored
  fingerprint lets the unlock command detect this, drop the wrap,
  and require a fresh enrolment after a master-password sign-in.
  No silent decryption with the wrong key.

What it explicitly does **not** change:

- The master password remains the only way to perform a *first*
  sign-in. The Yubikey wrap is created from an already-unlocked
  session and only replaces the unlock step on subsequent runs.
- The master password input remains available on the unlock view
  even when the Yubikey wrap is present, so a lost Yubikey does
  not lock the user out of their vault.
- The on-server material is unchanged. No server-side key escrow,
  no extra protocol field. The wrap is purely a local convenience.

## Optional: Approving SSH Signatures on a Phone

Built into the Linux and macOS builds (the `phone-approval` cargo feature, on by default; a build made with `--no-default-features` does not contain it, and neither does any Windows build). It does nothing until the user pairs a phone and turns the option on: no relay is contacted before that. When the SSH agent's confirmation policy asks before signing, a paired phone can answer instead of the local dialog, after a passkey user verification on the phone. The protocol and the relay are the Clavix Approve project's (its `PROTOCOL.md`, "Approve mode", and `DESKTOP_APPROVAL.md`); this section covers what Clavix adds.

What does not change:

- Clavix signs with the vault key, and only after an approval. The phone holds no SSH key and nothing is installed on servers.
- Only SSH user-auth requests bound with `session-bind@openssh.com` go to the phone, since the phone re-verifies the request and its bindings from the raw material. Git commit signing and clients that don't bind keep the local dialog only.

What Clavix enforces:

- An approval counts only when its proof verifies under the approval key recorded at pairing, and is bound to the channel, the request id and the hash of the request as sent. Everything else (no answer, relay error, malformed or unauthentic answer) is "unavailable" and leaves the decision to the dialog. It is never an approval, and never a deny on its own.
- The first answer wins and the other prompt is withdrawn. A deny from either side denies.
- With the confirmation set to "once per key per session", an approval is remembered until the agent stops (lock, logout, agent turned off). While a paired phone is asked, it is remembered for the destination the prompt showed only (the key and the host key of the bound session): the same key to another server asks again, on the phone and in the dialog, whichever of the two gave the first approval. Without a phone, the setting keeps its older meaning, once per key whatever the server. A request that names no destination (a client that does not bind its session, git signing) is remembered per key and never covers a server. Each approval writes one line to Clavix's standard error saying where it was given, so that a later login that goes through without a prompt can be traced to it.
- Session unlocked: the dialog at once, and the phone after the user's delay (0 = at once). Screen locked: the phone only, and the dialog comes back on unlock. The request may wait 90 s instead of 30 s once the phone is involved.
- Pairing (both modes) follows version 2 of the Clavix Approve pairing protocol. The QR code is a `clavix-approve://` link that opens the app, never a page served by the relay. The six digits are a commit-then-reveal short authentication string: Clavix commits to a nonce, the phone answers with its keys and its own nonce, and only then is Clavix's nonce revealed. A relay that learned the pairing secret has one chance in a million per code, and each failed try is a pairing the user refuses. Clavix keeps a phone only after the user confirmed the digits. A phone that answered and was not confirmed (digits differ, dialog closed, vault locked) is revoked on the relay, best effort, so it does not keep a pairing this computer never accepted.
- A pairing made under version 1 of the pairing protocol is recognised as such (it was stored without a protocol version). It stays visible so that it can be forgotten, but it is never used: no approval is asked of it, its keys are not offered while locked, and no phone can be added to it.
- The enrolment secret is the relay's own admission control, not a secret of the pairing: it is empty for a relay with open enrolment, and is not stored.
- The pairing (relay URL, bearer token, channel keys, the devices' public keys) is stored in `session.json`, encrypted with the user key. It is loaded on unlock and dropped from memory on lock, logout and auto-lock, together with the vault keys. It is never sent to the Vaultwarden server.

| Attacker | Effect |
|---|---|
| The relay or the network | Can delay or drop requests: the dialog still works, so the worst case is today's behaviour. Cannot forge an approval (it needs the phone's approval key) or replay one (bound to channel, request id and request hash). Sees metadata: channel ids, timing, sizes. |
| A malicious page served by the relay | Only matters to a user who pairs through the relay's web page by pasting the code, instead of the app. The page could then show a different destination to obtain a verification; its integrity is the relay operator's. Clavix's QR code never leads to it. |
| A relay that interferes with pairing | Cannot substitute its own keys without changing the six digits, which it cannot steer (see above). It can make pairing fail. |
| A process in the desktop session | Cannot approve by faking input while the screen is locked, when the phone is the only prompt. While the session is unlocked the dialog is shown, and that process can still click it, as before. |
| A thief with the unlocked phone | Needs the passkey's user verification for each approval. |
| A compromised desktop | No change: it holds the keys and can sign without asking anyone. |

Accepted new risk: a signature can now happen while the user is away from the desk, which the 30 s dialog timeout used to prevent. That is the point of the feature, and each signature still needs a verification on the phone.

Approving does not help once the vault is locked: the keys are gone, so there is nothing to approve. The settings say so, and point to the next section.

## Optional: Signing With the Phone's Key While the Vault Is Locked

Same feature flag, same builds, and a separate opt-in: a second pairing, in the Clavix Approve *sign mode* (the protocol fixes a channel's mode at pairing, so it cannot be the approve-mode channel above). It is what the standalone `clavix-agent` does, built into Clavix for the time the vault is locked.

What does not change: **a locked session holds no keys.** Every lock path (manual, tray, auto-lock) stops the vault agent and drops the vault keys, exactly as before. Nothing in this section keeps a vault key, or anything derived from one, in memory.

What happens instead, on a lock and at launch (Clavix starts locked), if a phone is paired in sign mode and "use it when the vault is locked" is on (not on logout: see below):

- Clavix starts a key-less agent on the same socket. Its only keys are the phones' public keys; each signature is made **on the phone**, with its own key (Secure Enclave), after the user approved there with biometrics. The phone's public key must be in the servers' `authorized_keys`: the user installs it, Clavix shows it after pairing.
- No local dialog: the vault is locked and there is no window to answer. The phone is the confirmation, for every signature.
- Only SSH user-auth requests on a connection bound with `session-bind@openssh.com`, for that very session, are sent to the phone; anything else is refused without contacting it (log line "connection has no session binding for authentication"). The phone re-verifies the request and the host's binding signature from the raw material and shows the destination under the name it pinned for the host key.
- The signature the phone returns is checked against the phone's key before it is answered.
- On unlock, the key-less agent stops before the vault agent starts again (or simply stops, if the vault agent does not restart on unlock).
- Logout ends sign mode on this machine: the key-less agent stops, the pairing files are deleted, and the pairing is revoked on the relay (best effort, in the background). Nothing is left to start the agent at the next launch, and a different account that logs in afterwards does not inherit the phone. The approve-mode pairing goes with `session.json`, and is revoked on the relay too when the vault is unlocked at logout. Pairing again is required after logging back in.

**Stored outside the vault.** It has to work while the vault is locked, so the pairing cannot be encrypted with the user key like the approve-mode one. It is kept like `clavix-agent` keeps it: the `clavix-approve-core` state file (relay URL, bearer token, this machine's channel keys, the phones' public keys) in `<config dir>/clavix/phone-sign/state.json`, plus the on/off switch in `options.json`, both 0600 in a 0700 directory (the feature is not built on Windows). The trade-off, accepted: these secrets only let a process **ask** a paired phone for a signature. The phone shows the destination, requires biometrics, and signs with a key that never leaves it; the secrets never sign anything. A process that reads them gains what any process able to reach the agent socket already has: the ability to send the phone a request the user can refuse.

| Attacker | Effect |
|---|---|
| A process running as the user while the vault is locked | Can use the agent socket, or the stored channel secrets, to send login requests to the phone. Each one shows its destination on the phone and needs biometrics; refusing denies, and after a denial further requests fail at once for 5 s, so a retry loop cannot turn into a stream of notifications. It cannot obtain a vault key: none is in memory. |
| The relay or the network | Can delay or drop requests (no signature: ssh fails or tries the next key). Cannot forge a signature (it needs the phone's key) or read a request (sealed end to end). |
| A thief with the unlocked phone | Needs the biometric check for each signature, as with `clavix-agent`. |
| A stolen disk with the vault locked | Gets the channel secrets: it can ask the phone, as above, from a machine of its choosing, until the pairing is forgotten (Settings revokes it on the relay). |

Accepted new risk: while the vault is locked, a server that trusts the phone's key can be reached with the phone's approval alone. That is the purpose of the option; turning it off, or forgetting the phone, ends it.

### Phone-only mode

Clavix can be used with no vault at all: no account, no server, no master password, only the key-less agent above for the phones paired in sign mode. The mode is chosen at first launch, or when signing out of a vault with the explicit choice to keep the phone. It is recorded in `<config dir>/clavix/mode.json`, which holds no secret and exists only on builds that have the phone features.

What the mode changes, and nothing else:

- **Pairing and forgetting a phone need no unlocked vault**, since there is none. In vault mode these still require the vault to be unlocked. Whoever can use the Clavix window of an unlocked desktop session can therefore pair another phone, whose key they would then have to install on a server themselves, or forget one. They cannot sign: every signature needs the phone's own confirmation (Face ID), for a destination the phone shows.
- **The agent runs whenever a phone is paired**, from launch, without the "use it when the vault is locked" switch, which is a vault-mode setting. It holds no private key, as in vault mode.
- **Signing out with "keep the phone"** keeps the sign-mode pairing and switches to this mode, instead of deleting the pairing. This is the one case where an agent runs after a logout; it is never the default. The vault session, its cache and the approve-mode pairing are removed as in any logout.

The mode cannot be entered while a vault account is stored on the machine, other than through that sign-out. Adding a vault later switches back to vault mode and keeps the pairing, with the "while locked" switch turned on. A process running as the user can write `mode.json`; it could as well read the pairing files or talk to the agent socket, which the table above already accounts for, and the phone's confirmation remains the control.

### Known limitations of the phone features

An internal review of the phone features was done before they were enabled by default. Its findings in the pinned `clavix-approve-core` are fixed: a sign-mode request is withdrawn from the relay and the phone when `ssh` closes its connection or the request times out locally; the sign-mode pairing file is refused when other users can read or write it (Clavix then reports it and runs no locked-vault agent on it), its directory is put back to 0700 at each save, and it is replaced through a new, randomly named temporary file; the relay client follows no redirect and accepts plain `http` only for a literal loopback address. What remains:

- **The sign-mode files are protected by file permissions only.** They are not encrypted or authenticated. A process running as the user can read or replace them, which the table above already accounts for; a copy of the configuration directory (a backup, synced dotfiles) carries the channel secrets with it. `options.json`, next to the pairing, holds no secret and its mode is not checked when read.
- **A request already approved cannot be withdrawn.** If `ssh` gives up in the instant after the approval on the phone, the phone has signed a login nobody is waiting for. The signature is sealed for this computer and bound to one SSH session.
- **A refusal by the hosted relay is not shown where the request failed.** A relay that requires a subscription (HTTP 402), or whose subscription covers no more machines (HTTP 403), refuses requests, not pairings. `ssh` then only reports that the agent refused. The reason is on Clavix's standard error and, until a request gets through again, in Settings, SSH, next to the pairing; it is kept in memory only and is gone after a restart. On Linux a desktop notification says so too, once per pairing and change of state and at most once an hour; its text names no host and no key. macOS has no such notification yet.
- **macOS is built but has not been exercised on a device.** The code is the Unix code that Linux runs and CI compiles and unit-tests it on macOS, but no pairing or signature was tested there. The agent socket is in `~/Library/Caches/clavix` and the sign-mode files in `~/Library/Application Support/clavix`, which Time Machine backs up.
- **Windows has no phone features.** The storage relies on Unix file modes and the Windows agent (named pipe, Pageant) has no locked-vault counterpart. The settings do not show the phone blocks there.
- **The Flatpak build does not contain them yet**: it is built with `--no-default-features`.

## Optional: Command-Line Access

Linux and macOS builds only, and off until the user turns it on in the preferences ("Allow changes from the command line"). While it is on, Clavix listens on a Unix socket next to the SSH agent's (`$XDG_RUNTIME_DIR/clavix/cli.sock`, or the app's own runtime directory under Flatpak), and `clavix item …`, the same binary started as a short-lived client, sends it one request per connection. The client holds no key and never authenticates to the server: every write is made by the running app through the commands the window uses.

**What a request can do.** Create a login or a secure note in the personal vault; change the name, username, password, URLs, notes, folder or favourite flag of an existing item; archive, unarchive, move to the trash, restore.

**What no request can do.**

- Read anything. The protocol has no read operation, and a reply carries an item id or an error message, never item content. The one thing it discloses beyond the id of the item acted on: when a *name* given by the caller matches several items, the error lists their ids. A caller can therefore learn whether an item of a given exact name exists, and how many.
- Delete permanently. `delete` is the trash; emptying it stays in the window.
- Edit an item that asks for the master password (reprompt). The window asks for the password before opening such an item in the editor; the command line cannot ask, so it refuses. It can still archive or trash it, both reversible.
- Work while the vault is locked, or on a standalone (read-only) session. The socket answers with the reason.
- Keep the vault unlocked. A request does not count as user activity, so a script on a timer cannot hold the auto-lock off.

**Who can send a request.** The socket is 0600 in a 0700 directory, and each connection's peer uid is compared with the socket's owner; anything else is refused. As with the agent socket, this means *any process running as the user*.

| Who | What they get |
| --- | --- |
| A process running as the user, option on, vault unlocked | Can add items, overwrite fields of items whose id or exact name it knows, and archive or trash them. Overwritten passwords go to the item's password history (last five) and trashed items stay in the trash, so the damage is recoverable, but it is damage: a changed URL or a swapped password is not announced beyond the window refreshing. It cannot read a secret through this channel. |
| The same process, option off (the default) | Nothing: there is no socket. |
| Another user on the machine | Nothing: directory and socket permissions, then the peer uid check. |

The password of a new or edited item travels over the socket in clear, between two processes of the same user. It is never accepted as a command-line argument (visible in `ps` and kept in shell history), only on standard input.

The preference is stored in the WebView's local storage like the others. A process that can write there can turn the option on; it can equally read the session files, which this document already assumes of a process running as the user.

## Out of Scope for the Current Design

The current project does not attempt to solve:

- protection against local malware with user-level access
- hardened memory isolation between frontend and backend
- resistance to screenshots, screen readers, or shoulder surfing
- **per-item master-password reprompt as a security control.** Clavix
  honours Bitwarden's `reprompt` flag and asks for the master password
  before revealing a flagged item, but the flag is advisory by
  construction: the server does not enforce it, any other client may
  ignore it, and the decrypted vault is already in memory when the
  prompt appears. It raises the bar for someone at an unlocked screen,
  and nothing more. `verify_master_password` is a local KDF + unwrap
  check with no network round trip.
- enterprise policy controls
- forensic-grade deletion of secrets from swap, crash dumps, or all
  allocator internals

## Existing Mitigations

Current mitigations visible in the codebase include:

- `SecretString` and `ZeroizeOnDrop` for sensitive key material
- HMAC verification before AES-CBC decryption
- encrypted refresh token persistence
- encrypted SQLite cache
- auto-lock mirrored in Rust as a backend watchdog
- Unix file and socket permission tightening where applicable
- focused unit tests on crypto, auth/session helpers, SSH agent
  framing, and WebAuthn challenge parsing

These mitigations reduce risk; they do not replace external review.

## Open Questions for Future Review

- Are all decrypted secrets kept for the minimum necessary lifetime?
- Is the Tauri command surface too broad, or missing validation in any
  command path?
- Are there platform-specific permission or path issues on macOS and
  Windows not visible from Linux-centric testing?
- Crash windows in move/share are currently **not** auto-recovered: the
  pre-operation snapshots and op-log entries written by `cache.rs` are
  not replayed on restart. Reviewers should treat this as a known gap
  rather than as a mitigation, and assess whether the resulting risk
  (locally inconsistent state until next successful sync) is acceptable.
- Is the SSH agent feature acceptable for the intended threat model, or
  should it be more isolated or more explicit about risk?
