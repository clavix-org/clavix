//! Clavix SSH agent — one wire protocol (draft-miller-ssh-agent: 4-byte
//! big-endian length + message), three transports:
//!
//! - **Unix socket** (`SSH_AUTH_SOCK`): `ssh` and friends on Linux/macOS.
//! - **Windows OpenSSH named pipe** `\\.\pipe\openssh-ssh-agent`:
//!   ssh.exe / ssh-add / git-for-windows probe that pipe automatically —
//!   no environment variable involved.
//! - **Windows PuTTY Pageant IPC**: a hidden `Pageant`-class window plus
//!   the `PageantRequest%08x` shared-memory channel, so plink / pscp /
//!   putty can use the vault keys too.
//!
//! Everything platform-neutral lives in `proto`; `unix` and `windows` only
//! differ in how connections arrive and how the caller is identified.

mod proto {
    //! Platform-neutral core: the key store, the sign-approval policy, the
    //! message handlers and the framing shared by every transport.

    use std::collections::HashSet;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use ed25519_dalek::{Signer as _, SigningKey};
    use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::RsaPrivateKey;
    use sha2::{Sha256, Sha512};
    use ssh_key::{Algorithm, HashAlg, PrivateKey};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::sync::Mutex;

    use clavix_core::error::{Error, Result};

    // Agent protocol message types (draft-miller-ssh-agent).
    pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
    pub const SSH_AGENT_FAILURE: u8 = 5;
    pub const SSH_AGENT_SUCCESS: u8 = 6;
    pub const SSH_AGENTC_EXTENSION: u8 = 27;

    /// OpenSSH >= 8.9 binds each agent connection to the SSH session it
    /// serves (PROTOCOL.agent, "session-bind@openssh.com").
    pub const EXT_SESSION_BIND: &[u8] = b"session-bind@openssh.com";
    /// Same cap as OpenSSH's `AGENT_MAX_SESSION_IDS`: a forwarding chain
    /// deeper than this is not a real use case, only a memory sink.
    pub const MAX_SESSION_BINDS: usize = 16;
    /// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252), the byte that follows the
    /// session identifier in the data a client asks us to sign for
    /// public-key authentication.
    const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

    // Flags on `SSH_AGENTC_SIGN_REQUEST`: which SHA variant for RSA.
    pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
    pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

    // Cap any single agent request to 256 KB — real traffic is orders smaller.
    pub const MAX_MESSAGE: usize = 256 * 1024;

    pub enum SignerKind {
        Ed25519(SigningKey),
        Rsa(RsaPrivateKey),
        /// NIST P-256/384/521. Signed through `ssh-key`, which picks the
        /// curve's hash (SHA-256/384/512) and encodes the `(r, s)` pair the
        /// way RFC 5656 wants it.
        Ecdsa(Box<PrivateKey>),
        /// A key that never leaves a paired phone (Clavix Approve, sign
        /// mode): the agent holds only its public half and has the phone
        /// sign, after the user approved there. What the agent offers
        /// while the vault is locked — no vault key is in memory then.
        #[cfg_attr(not(phone_approval), allow(dead_code))]
        Phone(Arc<dyn PhoneSigner>),
    }

    /// Outcome of a phone signature: the complete SSH signature blob, or
    /// why there is none (one line, for the log).
    pub type PhoneSignFuture =
        Pin<Box<dyn Future<Output = std::result::Result<Vec<u8>, String>> + Send>>;

    /// Has a paired phone sign with its own key. Implemented over the
    /// Clavix Approve relay (`phone_sign_relay`); tests use fakes. Kept
    /// here as a trait so this module stays free of the relay client.
    pub trait PhoneSigner: Send + Sync {
        /// Send `req` to the phone holding `req.key_blob` and wait for its
        /// signature. Must give up by itself (`Err`) after its timeout.
        fn sign(&self, req: SignRequest) -> PhoneSignFuture;
    }

    #[cfg_attr(not(phone_approval), allow(dead_code))]
    impl AgentKey {
        /// A phone-held key, from its SSH public key blob.
        pub fn phone(
            pub_blob: Vec<u8>,
            comment: String,
            signer: Arc<dyn PhoneSigner>,
        ) -> Result<Self> {
            let public = ssh_key::PublicKey::from_bytes(&pub_blob).map_err(|e| Error::Crypto {
                reason: format!("phone key: {e}"),
            })?;
            Ok(Self {
                algorithm: public.algorithm().to_string(),
                fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
                pub_blob,
                comment,
                kind: SignerKind::Phone(signer),
            })
        }
    }

    pub struct AgentKey {
        /// SSH wire-format public key blob (what clients compare against).
        pub pub_blob: Vec<u8>,
        pub comment: String,
        /// Wire-format SSH algorithm name, e.g. `"ssh-ed25519"` or `"ssh-rsa"`.
        pub algorithm: String,
        /// `"SHA256:…"` fingerprint of the public key, matches what
        /// `ssh-add -l` would print.
        pub fingerprint: String,
        pub kind: SignerKind,
    }

    /// Slim, signing-material-free summary of an exposed key — what the
    /// agent status surface returns to the front-end. Mirrors the rows
    /// you'd see from `ssh-add -l`.
    #[derive(Debug, Clone)]
    pub struct KeyInfo {
        pub comment: String,
        pub algorithm: String,
        pub fingerprint: String,
    }

    /// Best-effort identity of the process on the other end of an agent
    /// connection, shown in the confirmation prompt so the user can tell a
    /// `git push` they just ran from a signature they never asked for.
    ///
    /// This is INDICATIVE, NOT A SECURITY BOUNDARY. The OS vouches for the
    /// pid at connect time, but pids are recycled and process names are
    /// unauthenticated labels the process itself can change. Never gate a
    /// trust decision on it — it exists to help a human recognise their
    /// own action.
    ///
    /// Some transports cannot identify the caller at all (PuTTY's Pageant
    /// IPC carries no client identity): those connections get `None`.
    #[derive(Debug, Clone)]
    pub struct CallerInfo {
        pub pid: u32,
        /// Process name, when it can be read. `None` on platforms or
        /// transports where it is unavailable.
        pub name: Option<String>,
    }

    /// One `session-bind@openssh.com` binding: a server host key whose
    /// signature over the session identifier we verified, so we know the
    /// SSH client really holds a session with that host.
    ///
    /// Unlike `CallerInfo`, the host key IS authenticated — but a host key
    /// is not a host name. The name shown to the user comes from matching
    /// the key against `known_hosts`, i.e. from what the user already
    /// accepted for that key.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct HostHop {
        /// SSH wire-format public host key.
        pub key_blob: Vec<u8>,
        /// `"SHA256:…"` fingerprint of the host key.
        pub fingerprint: String,
        /// `true` when this hop carries a forwarded agent (`ssh -A`),
        /// `false` when the binding is for authenticating to that host.
        pub forwarded: bool,
        /// Exchange hash of the bound session.
        pub session_id: Vec<u8>,
        /// The host key's signature over `session_id`, as received and
        /// verified. Kept so a paired phone can verify the binding again
        /// on its own instead of trusting this agent's word for it.
        pub signature: Vec<u8>,
    }

    /// What the user is being asked to approve: the key, plus whoever asked.
    #[derive(Debug, Clone)]
    pub struct SignRequest {
        pub key: KeyInfo,
        /// SSH wire-format public key blob of the key that would sign.
        pub key_blob: Vec<u8>,
        /// The exact bytes that would be signed.
        pub data: Vec<u8>,
        /// Agent sign-request flags (RSA hash selection).
        pub flags: u32,
        pub caller: Option<CallerInfo>,
        /// Session bindings of the requesting connection, outermost first:
        /// `[host1 (forwarded), host2 (auth)]` means "authenticate to
        /// host2 from host1, through the agent forwarded to host1". Empty
        /// for clients that don't bind (OpenSSH < 8.9, git signing, PuTTY).
        pub hops: Vec<HostHop>,
    }

    impl SignRequest {
        /// Whether a paired phone can check this request on its own: an
        /// SSH user-auth request on a connection bound for authentication,
        /// for that very session (`handle_sign` already enforced the
        /// match). Anything else — git `SSHSIG`, clients that don't bind,
        /// PuTTY — carries nothing the phone could verify, so it gets the
        /// local dialog only.
        pub fn phone_eligible(&self) -> bool {
            let Some((sid, host_key)) = parse_userauth_request(&self.data) else {
                return false;
            };
            let Some(last) = self.hops.last().filter(|h| !h.forwarded) else {
                return false;
            };
            sid == last.session_id.as_slice()
                && host_key.is_none_or(|hk| hk == last.key_blob.as_slice())
        }
    }

    /// Per-connection agent state. `session-bind` is scoped to the
    /// connection it arrives on, so every transport creates one of these
    /// per client connection (Pageant, which has no connections, uses a
    /// fresh one per message).
    #[derive(Debug, Default)]
    pub struct ConnState {
        pub hops: Vec<HostHop>,
        /// Set once the client has closed its end (`serve` watches for it
        /// while a request is being answered).
        pub client_gone: ClientGone,
    }

    /// "The client closed the connection", for whoever is still working
    /// on its request. A signature nobody waits for must not stay on the
    /// user's phone: `ssh` gave up (Ctrl-C, its own timeout), and an
    /// approval given now would sign for nothing.
    #[derive(Debug, Default, Clone)]
    pub struct ClientGone(Arc<(std::sync::atomic::AtomicBool, tokio::sync::Notify)>);

    impl ClientGone {
        fn set(&self) {
            self.0 .0.store(true, std::sync::atomic::Ordering::SeqCst);
            self.0 .1.notify_waiters();
        }

        /// Resolves once the client is gone (at once if it already is).
        async fn wait(&self) {
            // Waiter registered before the flag is read, as in
            // `SignGuard::stopped`.
            let notified = self.0 .1.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.0 .0.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    impl ConnState {
        /// The last binding, if it was for authentication. OpenSSH treats
        /// such a connection as spent for further binds, and expects any
        /// user-auth signature on it to be for that very session.
        fn bound_for_auth(&self) -> Option<&HostHop> {
            self.hops.last().filter(|h| !h.forwarded)
        }
    }

    impl From<&AgentKey> for KeyInfo {
        fn from(k: &AgentKey) -> Self {
            Self {
                comment: k.comment.clone(),
                algorithm: k.algorithm.clone(),
                fingerprint: k.fingerprint.clone(),
            }
        }
    }

    pub type KeyStore = Arc<Mutex<Vec<AgentKey>>>;

    /// When the agent asks the user to approve a signature.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SignPolicy {
        /// Sign silently (historical behaviour).
        Never,
        /// Ask once per key per agent run, then remember that key: for
        /// every destination, or for the approved one only (see
        /// `SignGuard::remembering_per_host`).
        PerSession,
        /// Ask before every signature.
        Always,
    }

    /// Async "ask the user to approve this signature" callback. Returns
    /// `true` to allow. Kept as a boxed future so `ssh_agent` stays free
    /// of any Tauri dependency — `commands::ssh` supplies the real
    /// implementation that drives the confirmation dialog.
    pub type ConfirmFn =
        Arc<dyn Fn(SignRequest) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

    /// Whether an approval remembered under `PerSession` is for the
    /// destination it was given for only. Asked at each request: the
    /// setting behind it can change while the agent runs.
    pub type PerHostFn = Arc<dyn Fn() -> bool + Send + Sync>;

    /// What one remembered approval covers: a key, and the host key of the
    /// destination it was approved for, or `None` for "whatever the
    /// destination" (and for requests that name none).
    type Approval = (String, Option<Vec<u8>>);

    /// Signature-authorization policy for a running agent, plus the
    /// per-run set of keys already approved under `PerSession`.
    #[derive(Clone)]
    pub struct SignGuard {
        policy: SignPolicy,
        confirm: Option<ConfirmFn>,
        /// Approvals given during this agent run (PerSession only). The
        /// set dies with the guard: a lock or a logout stops the agent,
        /// and the next one starts with nothing remembered.
        approved: Arc<Mutex<HashSet<Approval>>>,
        per_host: Option<PerHostFn>,
        /// Set when the agent starts stopping: every parked authorization
        /// resolves to "denied" immediately instead of waiting out the
        /// confirmation timeout. This is what keeps `stop()` from ever
        /// blocking on a prompt the user can no longer see — it must not
        /// depend on the *caller* remembering to clear the prompts first.
        cancelled: Arc<std::sync::atomic::AtomicBool>,
        cancel_notify: Arc<tokio::sync::Notify>,
    }

    impl SignGuard {
        pub fn new(policy: SignPolicy, confirm: Option<ConfirmFn>) -> Self {
            Self {
                policy,
                confirm,
                approved: Arc::new(Mutex::new(HashSet::new())),
                per_host: None,
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                cancel_notify: Arc::new(tokio::sync::Notify::new()),
            }
        }

        /// Under `PerSession`, remember an approval for its destination
        /// only while `per_host` says so.
        ///
        /// Meant for when a phone approves: the phone shows one
        /// destination, and its approval must not silently cover every
        /// other server that key opens until the next lock. The desktop
        /// dialog's approvals are scoped the same way then, so that the
        /// two answers to one prompt mean the same thing.
        pub fn remembering_per_host(mut self, per_host: PerHostFn) -> Self {
            self.per_host = Some(per_host);
            self
        }

        /// What an approval of `req` would cover.
        ///
        /// The destination is the host key of the session the connection
        /// is bound to, and only for a login to that very session
        /// (`phone_eligible`): that is what the prompt shows. Anything
        /// else (a client that does not bind, git signing) names no
        /// destination and is remembered per key, apart from any host.
        fn approval_for(&self, req: &SignRequest) -> Approval {
            let per_host = self.per_host.as_ref().is_some_and(|f| f());
            let host = (per_host && req.phone_eligible())
                .then(|| req.hops.last().map(|h| h.key_blob.clone()))
                .flatten();
            (req.key.fingerprint.clone(), host)
        }

        /// Deny every parked (and every later) authorization. Idempotent;
        /// called by the agent's stop paths.
        pub fn cancel(&self) {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.cancel_notify.notify_waiters();
        }

        /// The agent is stopping or has stopped: nothing may be listed or
        /// signed any more, on any connection, whatever the policy.
        pub fn is_cancelled(&self) -> bool {
            self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Resolves once the agent stops (at once if it already has).
        pub async fn stopped(&self) {
            // Waiter registered before the flag is read, as in `ask`.
            let notified = self.cancel_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }

        /// Decide whether a signature with `key` may proceed. Awaits the
        /// user only when the policy requires it; the caller must NOT hold
        /// the key-store lock across this call (it can block on a human).
        async fn authorize(&self, req: SignRequest) -> bool {
            // A stopped agent authorizes nothing. `ask` already refuses,
            // but `Never` and an already-approved `PerSession` key never
            // reach it: without this, a connection opened before the vault
            // locked could go on signing after it.
            if self.is_cancelled() {
                return false;
            }
            match self.policy {
                SignPolicy::Never => true,
                SignPolicy::Always => self.ask(req).await,
                SignPolicy::PerSession => {
                    // Keyed on the key, and on the destination when
                    // approvals are remembered per host. Never on the
                    // caller: that would re-prompt for every new `ssh`
                    // process, which is what `Always` already provides.
                    let approval = self.approval_for(&req);
                    if self.approved.lock().await.contains(&approval) {
                        return true;
                    }
                    let ok = self.ask(req).await;
                    if ok {
                        self.approved.lock().await.insert(approval);
                    }
                    ok
                }
            }
        }

        async fn ask(&self, req: SignRequest) -> bool {
            use std::sync::atomic::Ordering;

            // A confirming policy with no callback wired can't be
            // satisfied — deny rather than silently sign.
            let Some(confirm) = &self.confirm else {
                return false;
            };
            if self.cancelled.load(Ordering::SeqCst) {
                return false;
            }
            let answer = confirm(req);
            // Register the cancellation waiter *before* the second flag
            // check (`enable` closes the create-vs-notify race), so a
            // `cancel()` landing between the two loads still wins.
            let notified = self.cancel_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.cancelled.load(Ordering::SeqCst) {
                return false;
            }
            tokio::select! {
                approved = answer => approved,
                _ = notified => false,
            }
        }
    }

    /// Reduce an OS-supplied process label (Linux `/proc/<pid>/comm`, a
    /// Windows image file name) to a short, printable, single-line string:
    /// it is headed for a confirmation dialog and the process itself
    /// controls parts of it. Shared by both platforms' `process_name` —
    /// and compiled only where one of those callers exists (macOS resolves
    /// no label at all, so an unconditional copy here would be dead code).
    #[cfg(any(target_os = "linux", windows))]
    pub fn sanitize_process_label(raw: &str) -> Option<String> {
        let cleaned: String = raw
            .chars()
            .filter(|c| !c.is_control())
            .take(32)
            .collect::<String>()
            .trim()
            .to_string();
        (!cleaned.is_empty()).then_some(cleaned)
    }

    /// Parse an OpenSSH private key and wrap it as an `AgentKey` if we can
    /// sign with it. Today: Ed25519, RSA and ECDSA (NIST P-256/384/521).
    /// Returns `Ok(None)` for key types we intentionally skip (DSA, FIDO
    /// `sk-*` keys, which need the hardware token), `Err` for malformed or
    /// encrypted input.
    pub fn try_load_agent_key(
        private_key_pem: &str,
        public_comment: &str,
    ) -> Result<Option<AgentKey>> {
        let pk = PrivateKey::from_openssh(private_key_pem).map_err(|e| Error::Crypto {
            reason: format!("ssh key parse: {e}"),
        })?;
        if pk.is_encrypted() {
            return Err(Error::Crypto {
                reason: "SSH private key is passphrase-protected — decrypt it first".into(),
            });
        }
        let pub_blob = pk.public_key().to_bytes().map_err(|e| Error::Crypto {
            reason: format!("ssh public blob: {e}"),
        })?;
        let comment = if !pk.comment().is_empty() {
            pk.comment().to_string()
        } else {
            public_comment.to_string()
        };
        let algorithm = pk.algorithm().to_string();
        let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();
        let kind = match pk.algorithm() {
            Algorithm::Ed25519 => {
                let keypair = pk.key_data().ed25519().ok_or_else(|| Error::Crypto {
                    reason: "ed25519 keypair extraction failed".into(),
                })?;
                let secret_bytes: &[u8; 32] = keypair.private.as_ref();
                SignerKind::Ed25519(SigningKey::from_bytes(secret_bytes))
            }
            Algorithm::Rsa { .. } => {
                let keypair = pk.key_data().rsa().ok_or_else(|| Error::Crypto {
                    reason: "rsa keypair extraction failed".into(),
                })?;
                let n = rsa::BigUint::from_bytes_be(keypair.public.n.as_bytes());
                let e = rsa::BigUint::from_bytes_be(keypair.public.e.as_bytes());
                let d = rsa::BigUint::from_bytes_be(keypair.private.d.as_bytes());
                let p = rsa::BigUint::from_bytes_be(keypair.private.p.as_bytes());
                let q = rsa::BigUint::from_bytes_be(keypair.private.q.as_bytes());
                let rsa_key =
                    RsaPrivateKey::from_components(n, e, d, vec![p, q]).map_err(|err| {
                        Error::Crypto {
                            reason: format!("rsa key import: {err}"),
                        }
                    })?;
                SignerKind::Rsa(rsa_key)
            }
            Algorithm::Ecdsa { .. } => SignerKind::Ecdsa(Box::new(pk)),
            _ => return Ok(None),
        };
        Ok(Some(AgentKey {
            pub_blob,
            comment,
            algorithm,
            fingerprint,
            kind,
        }))
    }

    /// Run one agent message (type byte + body — what a socket would carry
    /// after its length prefix) and return the response *without* framing.
    /// Shared by every transport so the three endpoints cannot drift apart.
    pub async fn process_message(
        msg: &[u8],
        keys: &KeyStore,
        guard: &SignGuard,
        caller: Option<&CallerInfo>,
        conn: &mut ConnState,
    ) -> Vec<u8> {
        let Some((&msg_type, body)) = msg.split_first() else {
            return vec![SSH_AGENT_FAILURE];
        };
        // Stopped (the vault locked, the user logged out, the agent was
        // turned off): a connection that outlived the stop gets nothing,
        // not even the list of keys.
        if guard.is_cancelled() {
            return vec![SSH_AGENT_FAILURE];
        }
        match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => handle_list(keys).await,
            SSH_AGENTC_SIGN_REQUEST => handle_sign(keys, guard, body, caller, conn).await,
            SSH_AGENTC_EXTENSION => handle_extension(body, conn),
            _ => vec![SSH_AGENT_FAILURE],
        }
    }

    /// `SSH_AGENTC_EXTENSION`. Only `session-bind@openssh.com` is
    /// understood; anything else gets the generic failure, which is what
    /// PROTOCOL.agent prescribes for an unsupported extension.
    fn handle_extension(body: &[u8], conn: &mut ConnState) -> Vec<u8> {
        let mut reader = SshReader::new(body);
        match reader.read_string() {
            Ok(EXT_SESSION_BIND) => match session_bind(&mut reader, conn) {
                Some(()) => vec![SSH_AGENT_SUCCESS],
                None => vec![SSH_AGENT_FAILURE],
            },
            _ => vec![SSH_AGENT_FAILURE],
        }
    }

    /// Parse, verify and record one session binding:
    ///
    /// ```text
    /// string  hostkey
    /// string  session identifier
    /// string  signature (by hostkey, over the session identifier)
    /// bool    is_forwarding
    /// ```
    ///
    /// The rules mirror OpenSSH's `process_ext_session_bind`, so a client
    /// sees the same answers from Clavix as from `ssh-agent`. `None` means
    /// "refuse".
    fn session_bind(reader: &mut SshReader<'_>, conn: &mut ConnState) -> Option<()> {
        use rsa::signature::Verifier;
        use ssh_key::{PublicKey, Signature};

        let key_blob = reader.read_string().ok()?;
        let session_id = reader.read_string().ok()?;
        let sig_blob = reader.read_string().ok()?;
        let forwarded = match reader.read_u8().ok()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        if !reader.is_empty() {
            return None;
        }

        // The signature is what turns "the client says it talks to this
        // host" into "the client holds a session that this host key
        // signed". Without it a binding would be an unverified label.
        let host_key = PublicKey::from_bytes(key_blob).ok()?;
        let signature = Signature::try_from(sig_blob).ok()?;
        // Fully qualified: `PublicKey` also has an inherent `verify` for
        // SSHSIG (namespace + message), which is not this.
        Verifier::verify(&host_key, session_id, &signature).ok()?;

        // Re-binding a session already seen is fine (OpenSSH re-sends the
        // forwarding bind on every forwarded channel) as long as it names
        // the same host key; a different key for the same session is a lie.
        if let Some(existing) = conn.hops.iter().find(|h| h.session_id == session_id) {
            return (existing.key_blob == key_blob).then_some(());
        }
        // A connection bound for authentication is spent: nothing may be
        // chained after it.
        if conn.bound_for_auth().is_some() || conn.hops.len() >= MAX_SESSION_BINDS {
            return None;
        }
        conn.hops.push(HostHop {
            key_blob: key_blob.to_vec(),
            fingerprint: host_key.fingerprint(HashAlg::Sha256).to_string(),
            forwarded,
            session_id: session_id.to_vec(),
            signature: sig_blob.to_vec(),
        });
        Some(())
    }

    /// If `data` is a public-key user-auth request (RFC 4252 §7, plus
    /// OpenSSH's `publickey-hostbound-v00@openssh.com`), return its session
    /// identifier and, for the host-bound variant, the server host key it
    /// names. `None` for anything else (git's `SSHSIG`, arbitrary data).
    pub fn parse_userauth_request(data: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
        let mut r = SshReader::new(data);
        let session_id = r.read_string().ok()?;
        if r.read_u8().ok()? != SSH_MSG_USERAUTH_REQUEST {
            return None;
        }
        let _user = r.read_string().ok()?;
        let _service = r.read_string().ok()?;
        let hostbound = match r.read_string().ok()? {
            b"publickey" => false,
            b"publickey-hostbound-v00@openssh.com" => true,
            _ => return None,
        };
        if r.read_u8().ok()? != 1 {
            return None;
        }
        let _alg = r.read_string().ok()?;
        let _key = r.read_string().ok()?;
        let host_key = if hostbound {
            Some(r.read_string().ok()?)
        } else {
            None
        };
        r.is_empty().then_some((session_id, host_key))
    }

    /// Serve one connection: read length-prefixed requests until the peer
    /// disconnects, answering each with a length-prefixed response. The
    /// transport object (Unix socket, named pipe, …) is generic — framing
    /// and message handling are identical for every client.
    ///
    /// The connection ends when the agent stops: a client that connected
    /// while the vault was unlocked (a long-lived `ssh -A` session, say)
    /// must not keep a working agent, and the keys it holds, past the lock.
    /// Ending it here, rather than in each transport, also drops a request
    /// still waiting on the user or on the phone.
    pub async fn serve<S>(
        stream: S,
        keys: KeyStore,
        guard: SignGuard,
        caller: Option<CallerInfo>,
    ) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let stopped = guard.clone();
        tokio::select! {
            biased;
            _ = stopped.stopped() => Ok(()),
            served = serve_until_closed(stream, keys, guard, caller) => served,
        }
    }

    async fn serve_until_closed<S>(
        mut stream: S,
        keys: KeyStore,
        guard: SignGuard,
        caller: Option<CallerInfo>,
    ) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut conn = ConnState::default();
        let gone = conn.client_gone.clone();
        // What the client sent while its previous request was being
        // answered (see below): the start of its next one.
        let mut ahead: Vec<u8> = Vec::new();
        loop {
            let mut header = [0u8; 4];
            match read_buffered(&mut stream, &mut ahead, &mut header).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            }
            let len = u32::from_be_bytes(header) as usize;
            if len == 0 || len > MAX_MESSAGE {
                return Ok(());
            }
            let mut buf = vec![0u8; len];
            read_buffered(&mut stream, &mut ahead, &mut buf).await?;

            // Answering can wait on the phone for a long time. Keep an eye
            // on the socket meanwhile: a client that closes it gave up, and
            // the request in flight is told so. Anything it sends instead
            // (clients do not pipeline, but nothing forbids it) is kept for
            // the next round.
            let mut left = false;
            let response = {
                let work = process_message(&buf, &keys, &guard, caller.as_ref(), &mut conn);
                tokio::pin!(work);
                let mut chunk = [0u8; 512];
                let mut watching = true;
                loop {
                    tokio::select! {
                        biased;
                        response = &mut work => break response,
                        read = stream.read(&mut chunk), if watching => match read {
                            Ok(n) if n > 0 && ahead.len() + n <= MAX_MESSAGE + 4 => {
                                ahead.extend_from_slice(&chunk[..n]);
                            }
                            // Too much sent ahead: stop reading, let the
                            // socket buffer hold the rest.
                            Ok(n) if n > 0 => {
                                ahead.extend_from_slice(&chunk[..n]);
                                watching = false;
                            }
                            // End of stream, or a broken one.
                            _ => {
                                gone.set();
                                watching = false;
                                left = true;
                            }
                        },
                    }
                }
            };

            let len_bytes = u32::to_be_bytes(response.len() as u32);
            let written = async {
                stream.write_all(&len_bytes).await?;
                stream.write_all(&response).await?;
                stream.flush().await
            }
            .await;
            // A client that closed its end may still read (a half-close),
            // so the answer is sent all the same; that it usually cannot
            // be is not an error worth reporting.
            if left {
                return Ok(());
            }
            written?;
        }
    }

    /// `read_exact`, serving first what was already read from the stream.
    async fn read_buffered<S>(
        stream: &mut S,
        ahead: &mut Vec<u8>,
        out: &mut [u8],
    ) -> std::io::Result<()>
    where
        S: AsyncRead + Unpin,
    {
        let taken = ahead.len().min(out.len());
        out[..taken].copy_from_slice(&ahead[..taken]);
        ahead.drain(..taken);
        stream.read_exact(&mut out[taken..]).await.map(|_| ())
    }

    async fn handle_list(keys: &KeyStore) -> Vec<u8> {
        let guard = keys.lock().await;
        let mut out = Vec::with_capacity(64);
        out.push(SSH_AGENT_IDENTITIES_ANSWER);
        out.extend_from_slice(&u32::to_be_bytes(guard.len() as u32));
        for k in guard.iter() {
            write_string(&mut out, &k.pub_blob);
            write_string(&mut out, k.comment.as_bytes());
        }
        out
    }

    async fn handle_sign(
        keys: &KeyStore,
        guard: &SignGuard,
        payload: &[u8],
        caller: Option<&CallerInfo>,
        conn: &ConnState,
    ) -> Vec<u8> {
        let mut reader = SshReader::new(payload);
        let Ok(key_blob) = reader.read_string() else {
            return vec![SSH_AGENT_FAILURE];
        };
        let Ok(data) = reader.read_string() else {
            return vec![SSH_AGENT_FAILURE];
        };
        let flags = reader.read_u32().unwrap_or(0);

        // On a connection bound for authentication, a user-auth signature
        // must be for THAT session (and, host-bound, that host): otherwise
        // a hostile server holding a forwarded agent could relay another
        // session's challenge through a connection whose binding the user
        // is looking at. Same check as OpenSSH's ssh-agent. Data that
        // isn't a user-auth request (git commit signing) is left alone.
        if let Some(bound) = conn.bound_for_auth() {
            if let Some((sid, host_key)) = parse_userauth_request(data) {
                if sid != bound.session_id.as_slice()
                    || host_key.is_some_and(|hk| hk != bound.key_blob.as_slice())
                {
                    return vec![SSH_AGENT_FAILURE];
                }
            }
        }

        // Identify the key (and grab its public summary for the prompt)
        // under the lock, then release it: `authorize` can block on a
        // human for up to the confirmation timeout, and holding the store
        // lock across that would freeze every other agent request.
        let (key_info, phone) = {
            let store = keys.lock().await;
            let Some(k) = store.iter().find(|k| k.pub_blob == key_blob) else {
                return vec![SSH_AGENT_FAILURE];
            };
            let phone = match &k.kind {
                SignerKind::Phone(signer) => Some(signer.clone()),
                _ => None,
            };
            (KeyInfo::from(k), phone)
        };

        let request = SignRequest {
            key: key_info,
            key_blob: key_blob.to_vec(),
            data: data.to_vec(),
            flags,
            caller: caller.cloned(),
            hops: conn.hops.clone(),
        };
        // A phone key signs only what the phone can check on its own, as
        // in `clavix-agent`: an SSH login on a connection bound to that
        // very session. Refused here, early, without waking the phone up.
        if phone.is_some() {
            if conn.bound_for_auth().is_none() {
                eprintln!(
                    "[clavix agent] sign request refused: connection has no session binding \
                     for authentication"
                );
                return vec![SSH_AGENT_FAILURE];
            }
            if !request.phone_eligible() {
                eprintln!(
                    "[clavix agent] sign request refused: not a public-key user-auth request \
                     for the bound session"
                );
                return vec![SSH_AGENT_FAILURE];
            }
        }
        let phone_request = phone.as_ref().map(|_| request.clone());
        if !guard.authorize(request).await {
            return vec![SSH_AGENT_FAILURE];
        }
        if let (Some(signer), Some(request)) = (phone, phone_request) {
            // The key-store lock is not held here: the phone can take up
            // to its timeout, and every other request must go on.
            return phone_sign(signer.as_ref(), request, &conn.client_gone).await;
        }

        let store = keys.lock().await;
        // Authorized a moment ago, possibly after a long wait on the user:
        // the agent may have stopped since. Last check before the key is
        // used; a stop also empties the store, which the lookup below
        // then turns into a failure.
        if guard.is_cancelled() {
            return vec![SSH_AGENT_FAILURE];
        }
        let Some(key) = store.iter().find(|k| k.pub_blob == key_blob) else {
            return vec![SSH_AGENT_FAILURE];
        };

        let (algo_name, sig_bytes): (&'static [u8], Vec<u8>) = match &key.kind {
            SignerKind::Ecdsa(pk) => {
                // `ssh-key` emits the complete wire signature (algorithm
                // name + RFC 5656 `(r, s)` blob) — answer with it as is.
                use rsa::signature::Signer as _;
                let Some(sig_blob) = pk
                    .try_sign(data)
                    .ok()
                    .and_then(|sig| Vec::<u8>::try_from(sig).ok())
                else {
                    return vec![SSH_AGENT_FAILURE];
                };
                let mut out = Vec::with_capacity(sig_blob.len() + 5);
                out.push(SSH_AGENT_SIGN_RESPONSE);
                write_string(&mut out, &sig_blob);
                return out;
            }
            SignerKind::Ed25519(signer) => (b"ssh-ed25519", signer.sign(data).to_bytes().to_vec()),
            // Answered above, before the store was locked again.
            SignerKind::Phone(_) => return vec![SSH_AGENT_FAILURE],
            SignerKind::Rsa(rsa_key) => {
                // flags=4 → SHA-512, flags=2 → SHA-256, legacy flags=0
                // (SHA-1 / ssh-rsa) is deprecated — we degrade it to SHA-256
                // since modern servers no longer accept SHA-1 signatures.
                let mut rng = rand::thread_rng();
                match flags {
                    SSH_AGENT_RSA_SHA2_512 => {
                        let signing_key = RsaSigningKey::<Sha512>::new(rsa_key.clone());
                        let sig: RsaSignature = signing_key.sign_with_rng(&mut rng, data);
                        (b"rsa-sha2-512", sig.to_bytes().to_vec())
                    }
                    _ => {
                        // flags=0 (legacy ssh-rsa/SHA-1) or flags=2 (SHA-256)
                        let _ = SSH_AGENT_RSA_SHA2_256; // name retained for clarity
                        let signing_key = RsaSigningKey::<Sha256>::new(rsa_key.clone());
                        let sig: RsaSignature = signing_key.sign_with_rng(&mut rng, data);
                        (b"rsa-sha2-256", sig.to_bytes().to_vec())
                    }
                }
            }
        };

        let mut sig_blob = Vec::with_capacity(96);
        write_string(&mut sig_blob, algo_name);
        write_string(&mut sig_blob, &sig_bytes);

        let mut out = Vec::with_capacity(sig_blob.len() + 5);
        out.push(SSH_AGENT_SIGN_RESPONSE);
        write_string(&mut out, &sig_blob);
        out
    }

    /// Have the phone sign `request` and answer with its signature, once
    /// it verifies under the requested key. One log line per request,
    /// whatever its outcome, with how long the phone took — the figure
    /// that matters against sshd's `LoginGraceTime`.
    ///
    /// A client that closes the connection meanwhile ends the wait:
    /// dropping the signer's future withdraws the request from the phone.
    async fn phone_sign(
        signer: &dyn PhoneSigner,
        request: SignRequest,
        client_gone: &ClientGone,
    ) -> Vec<u8> {
        use rsa::signature::Verifier;

        let destination = request
            .hops
            .last()
            .map(|h| h.fingerprint.clone())
            .unwrap_or_default();
        let (key_blob, data) = (request.key_blob.clone(), request.data.clone());
        let started = std::time::Instant::now();
        let answer = tokio::select! {
            answer = signer.sign(request) => answer,
            () = client_gone.wait() => Err("the client closed the connection".to_string()),
        };
        let waited = started.elapsed().as_secs_f32();
        let sig_blob = match answer {
            Ok(sig) => sig,
            Err(reason) => {
                eprintln!(
                    "[clavix agent] no signature from the phone for {destination} after \
                     {waited:.1} s: {reason}"
                );
                return vec![SSH_AGENT_FAILURE];
            }
        };
        // A wrong signature would only fail later, at the server, with a
        // less useful message.
        let valid = ssh_key::PublicKey::from_bytes(&key_blob)
            .ok()
            .zip(ssh_key::Signature::try_from(sig_blob.as_slice()).ok())
            .is_some_and(|(key, sig)| Verifier::verify(&key, &data, &sig).is_ok());
        if !valid {
            eprintln!(
                "[clavix agent] the phone returned a signature that does not verify for \
                 {destination} after {waited:.1} s; dropped"
            );
            return vec![SSH_AGENT_FAILURE];
        }
        eprintln!("[clavix agent] signed by the phone for {destination} after {waited:.1} s");
        let mut out = Vec::with_capacity(sig_blob.len() + 5);
        out.push(SSH_AGENT_SIGN_RESPONSE);
        write_string(&mut out, &sig_blob);
        out
    }

    pub fn write_string(buf: &mut Vec<u8>, s: &[u8]) {
        buf.extend_from_slice(&u32::to_be_bytes(s.len() as u32));
        buf.extend_from_slice(s);
    }

    pub struct SshReader<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> SshReader<'a> {
        pub fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        pub fn read_u32(&mut self) -> std::io::Result<u32> {
            if self.pos + 4 > self.buf.len() {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            let n = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
            self.pos += 4;
            Ok(n)
        }

        pub fn read_u8(&mut self) -> std::io::Result<u8> {
            let b = *self
                .buf
                .get(self.pos)
                .ok_or(std::io::ErrorKind::UnexpectedEof)?;
            self.pos += 1;
            Ok(b)
        }

        /// `true` once every byte has been consumed.
        pub fn is_empty(&self) -> bool {
            self.pos >= self.buf.len()
        }

        pub fn read_string(&mut self) -> std::io::Result<&'a [u8]> {
            let len = self.read_u32()? as usize;
            if self.pos + len > self.buf.len() {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            let slice = &self.buf[self.pos..self.pos + len];
            self.pos += len;
            Ok(slice)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn write_string_prepends_big_endian_length() {
            let mut out = Vec::new();
            write_string(&mut out, b"abc");
            assert_eq!(out, vec![0, 0, 0, 3, b'a', b'b', b'c']);
            write_string(&mut out, &[]);
            assert_eq!(&out[7..], &[0, 0, 0, 0]);
        }

        #[test]
        fn ssh_reader_roundtrip_matches_write_string() {
            let mut buf = Vec::new();
            write_string(&mut buf, b"ssh-ed25519");
            write_string(&mut buf, &[0xDE, 0xAD, 0xBE, 0xEF]);
            buf.extend_from_slice(&u32::to_be_bytes(42));

            let mut r = SshReader::new(&buf);
            assert_eq!(r.read_string().unwrap(), b"ssh-ed25519");
            assert_eq!(r.read_string().unwrap(), &[0xDE, 0xAD, 0xBE, 0xEF]);
            assert_eq!(r.read_u32().unwrap(), 42);
        }

        #[test]
        fn ssh_reader_rejects_truncated_length() {
            let buf = [0, 0, 0, 10, b'x']; // claims 10 bytes but only 1 available
            let mut r = SshReader::new(&buf);
            assert!(r.read_string().is_err());
        }

        #[test]
        fn ssh_reader_rejects_short_u32() {
            let buf = [0, 0, 0];
            let mut r = SshReader::new(&buf);
            assert!(r.read_u32().is_err());
        }

        #[test]
        fn handle_list_frames_empty_identities_answer() {
            use tokio::runtime::Runtime;
            let rt = Runtime::new().unwrap();
            let keys: KeyStore = Arc::new(Mutex::new(Vec::new()));
            let out = rt.block_on(handle_list(&keys));
            assert_eq!(out[0], SSH_AGENT_IDENTITIES_ANSWER);
            assert_eq!(&out[1..5], &[0, 0, 0, 0]); // zero identities
            assert_eq!(out.len(), 5);
        }

        #[test]
        fn handle_sign_fails_on_unknown_key_blob() {
            use tokio::runtime::Runtime;
            let rt = Runtime::new().unwrap();
            let keys: KeyStore = Arc::new(Mutex::new(Vec::new()));
            // Build a valid sign_request frame for a blob nobody has.
            let mut payload = Vec::new();
            write_string(&mut payload, b"unknown-blob");
            write_string(&mut payload, b"data-to-sign");
            payload.extend_from_slice(&u32::to_be_bytes(0)); // flags

            let guard = SignGuard::new(SignPolicy::Never, None);
            let out = rt.block_on(handle_sign(
                &keys,
                &guard,
                &payload,
                None,
                &ConnState::default(),
            ));
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);
        }

        #[test]
        fn process_message_answers_failure_for_unknown_types() {
            use tokio::runtime::Runtime;
            let rt = Runtime::new().unwrap();
            let keys: KeyStore = Arc::new(Mutex::new(Vec::new()));
            let guard = SignGuard::new(SignPolicy::Never, None);
            let mut conn = ConnState::default();
            let out = rt.block_on(process_message(&[0x42], &keys, &guard, None, &mut conn));
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);
            // A truncated message (no type byte) must fail, not panic.
            let out = rt.block_on(process_message(&[], &keys, &guard, None, &mut conn));
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);
        }

        fn dummy_key(fp: &str) -> KeyInfo {
            KeyInfo {
                comment: "k".into(),
                algorithm: "ssh-ed25519".into(),
                fingerprint: fp.into(),
            }
        }

        fn req_for(key: &KeyInfo) -> SignRequest {
            SignRequest {
                key: key.clone(),
                key_blob: Vec::new(),
                data: Vec::new(),
                flags: 0,
                caller: None,
                hops: Vec::new(),
            }
        }

        fn counting_confirm(answer: bool, calls: Arc<Mutex<u32>>) -> ConfirmFn {
            Arc::new(move |_req: SignRequest| {
                let calls = calls.clone();
                Box::pin(async move {
                    *calls.lock().await += 1;
                    answer
                })
            })
        }

        #[test]
        fn authorize_never_signs_without_asking() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let g = SignGuard::new(
                SignPolicy::Never,
                Some(counting_confirm(false, calls.clone())),
            );
            assert!(rt.block_on(g.authorize(req_for(&dummy_key("SHA256:a")))));
            assert_eq!(rt.block_on(async { *calls.lock().await }), 0);
        }

        #[test]
        fn authorize_always_asks_every_time() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let g = SignGuard::new(
                SignPolicy::Always,
                Some(counting_confirm(true, calls.clone())),
            );
            let k = dummy_key("SHA256:a");
            assert!(rt.block_on(g.authorize(req_for(&k))));
            assert!(rt.block_on(g.authorize(req_for(&k))));
            assert_eq!(rt.block_on(async { *calls.lock().await }), 2);
        }

        #[test]
        fn authorize_always_denies_on_reject() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let g = SignGuard::new(SignPolicy::Always, Some(counting_confirm(false, calls)));
            assert!(!rt.block_on(g.authorize(req_for(&dummy_key("SHA256:a")))));
        }

        /// A login to `host`, on a connection bound to that session: what
        /// the prompt (and the phone) shows a destination for.
        fn login(key: &KeyInfo, host: &HostKey, sid: &[u8]) -> SignRequest {
            let mut conn = ConnState::default();
            assert_eq!(bind(&mut conn, host, sid, false), vec![SSH_AGENT_SUCCESS]);
            SignRequest {
                hops: conn.hops,
                data: userauth(sid, Some(&host.blob())),
                ..req_for(key)
            }
        }

        fn per_host_guard(
            on: Arc<std::sync::atomic::AtomicBool>,
            calls: Arc<Mutex<u32>>,
        ) -> SignGuard {
            SignGuard::new(SignPolicy::PerSession, Some(counting_confirm(true, calls)))
                .remembering_per_host(Arc::new(move || {
                    on.load(std::sync::atomic::Ordering::SeqCst)
                }))
        }

        /// With a phone approving, "once per session" remembers the
        /// approval for the server it was given for: the same key to a
        /// new server asks again, the same server does not.
        #[test]
        fn per_session_remembers_an_approval_for_its_destination_only() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let asked = || rt.block_on(async { *calls.lock().await });
            let on = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let g = per_host_guard(on, calls.clone());
            let key = dummy_key("SHA256:a");
            let (web, db) = (HostKey::new(1), HostKey::new(2));

            assert!(rt.block_on(g.authorize(login(&key, &web, b"sid-1"))));
            assert_eq!(asked(), 1);
            // Same key, same server, another ssh session: remembered.
            assert!(rt.block_on(g.authorize(login(&key, &web, b"sid-2"))));
            assert_eq!(asked(), 1);
            // Same key, another server: asked again.
            assert!(rt.block_on(g.authorize(login(&key, &db, b"sid-3"))));
            assert_eq!(asked(), 2);
            assert!(rt.block_on(g.authorize(login(&key, &db, b"sid-4"))));
            assert_eq!(asked(), 2);
            // Another key to an approved server: asked.
            assert!(rt.block_on(g.authorize(login(&dummy_key("SHA256:b"), &web, b"sid-5"))));
            assert_eq!(asked(), 3);

            // A request that names no destination (git signing, a client
            // that does not bind) is remembered per key, and covers no
            // server: nor is it covered by one.
            assert!(rt.block_on(g.authorize(req_for(&key))));
            assert_eq!(asked(), 4);
            assert!(rt.block_on(g.authorize(req_for(&key))));
            assert_eq!(asked(), 4);
            assert!(rt.block_on(g.authorize(login(&key, &HostKey::new(3), b"sid-6"))));
            assert_eq!(asked(), 5);
        }

        /// Without a phone, the setting keeps its meaning: once per key,
        /// whatever the server. And an approval given that way stops
        /// covering servers the moment a phone is asked.
        #[test]
        fn per_session_is_per_key_until_approvals_are_per_host() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let asked = || rt.block_on(async { *calls.lock().await });
            let on = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let g = per_host_guard(on.clone(), calls.clone());
            let key = dummy_key("SHA256:a");
            let (web, db) = (HostKey::new(1), HostKey::new(2));

            assert!(rt.block_on(g.authorize(login(&key, &web, b"sid-1"))));
            assert!(rt.block_on(g.authorize(login(&key, &db, b"sid-2"))));
            assert_eq!(asked(), 1);

            on.store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(rt.block_on(g.authorize(login(&key, &db, b"sid-3"))));
            assert_eq!(asked(), 2);
        }

        /// A lock or a logout stops the agent; the next one is built
        /// with a new guard. Nothing approved before is remembered, and
        /// the stopped guard authorizes nothing, remembered or not.
        #[test]
        fn a_lock_forgets_every_remembered_approval() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let asked = || rt.block_on(async { *calls.lock().await });
            let on = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let key = dummy_key("SHA256:a");
            let web = HostKey::new(1);

            let before = per_host_guard(on.clone(), calls.clone());
            assert!(rt.block_on(before.authorize(login(&key, &web, b"sid-1"))));
            assert!(rt.block_on(before.authorize(login(&key, &web, b"sid-2"))));
            assert_eq!(asked(), 1);

            // The lock: what `stop()` does to the running agent's guard.
            before.cancel();
            assert!(!rt.block_on(before.authorize(login(&key, &web, b"sid-3"))));
            assert_eq!(asked(), 1);

            // The unlock: a new agent, a new guard.
            let after = per_host_guard(on, calls.clone());
            assert!(rt.block_on(after.authorize(login(&key, &web, b"sid-4"))));
            assert_eq!(asked(), 2);
        }

        #[test]
        fn authorize_per_session_asks_once_per_key() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let g = SignGuard::new(
                SignPolicy::PerSession,
                Some(counting_confirm(true, calls.clone())),
            );
            let a = dummy_key("SHA256:a");
            let b = dummy_key("SHA256:b");
            assert!(rt.block_on(g.authorize(req_for(&a))));
            assert!(rt.block_on(g.authorize(req_for(&a)))); // remembered — no second ask
            assert!(rt.block_on(g.authorize(req_for(&b)))); // different key — asks again
            assert_eq!(rt.block_on(async { *calls.lock().await }), 2);
        }

        #[test]
        fn authorize_per_session_reject_is_not_remembered() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let g = SignGuard::new(
                SignPolicy::PerSession,
                Some(counting_confirm(false, calls.clone())),
            );
            let a = dummy_key("SHA256:a");
            assert!(!rt.block_on(g.authorize(req_for(&a))));
            assert!(!rt.block_on(g.authorize(req_for(&a))));
            assert_eq!(rt.block_on(async { *calls.lock().await }), 2); // re-asked
        }

        #[test]
        fn authorize_confirming_policy_without_callback_denies() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let g = SignGuard::new(SignPolicy::Always, None);
            assert!(!rt.block_on(g.authorize(req_for(&dummy_key("SHA256:a")))));
        }

        /// One Ed25519 key in a store, and a sign request for it.
        fn store_with_a_key() -> (KeyStore, Vec<u8>) {
            let blob = b"stop-test-key".to_vec();
            let keys: KeyStore = Arc::new(Mutex::new(vec![AgentKey {
                pub_blob: blob.clone(),
                comment: "vault".into(),
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:stop".into(),
                kind: SignerKind::Ed25519(SigningKey::from_bytes(&[7u8; 32])),
            }]));
            let mut sign = vec![SSH_AGENTC_SIGN_REQUEST];
            write_string(&mut sign, &blob);
            write_string(&mut sign, b"data");
            sign.extend_from_slice(&u32::to_be_bytes(0));
            (keys, sign)
        }

        /// The vault locked: `stop` cancelled the guard. A connection that
        /// was already open must get nothing more, under the policies that
        /// never reach `ask`: `Never`, and `PerSession` once approved.
        #[tokio::test]
        async fn a_stopped_agent_neither_lists_nor_signs() {
            let calls = Arc::new(Mutex::new(0u32));
            for guard in [
                SignGuard::new(SignPolicy::Never, None),
                SignGuard::new(
                    SignPolicy::PerSession,
                    Some(counting_confirm(true, calls.clone())),
                ),
            ] {
                let (keys, sign) = store_with_a_key();
                let mut conn = ConnState::default();
                let list = [SSH_AGENTC_REQUEST_IDENTITIES];

                let out = process_message(&list, &keys, &guard, None, &mut conn).await;
                assert_eq!(out[0], SSH_AGENT_IDENTITIES_ANSWER);
                assert_eq!(&out[1..5], &[0, 0, 0, 1]);
                // Signs (and, per session, records the approval).
                let out = process_message(&sign, &keys, &guard, None, &mut conn).await;
                assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);

                guard.cancel();

                let out = process_message(&list, &keys, &guard, None, &mut conn).await;
                assert_eq!(out, vec![SSH_AGENT_FAILURE], "keys listed after the stop");
                let out = process_message(&sign, &keys, &guard, None, &mut conn).await;
                assert_eq!(out, vec![SSH_AGENT_FAILURE], "signed after the stop");
                // Not only `process_message`: the two layers under it too.
                assert!(!guard.authorize(req_for(&dummy_key("SHA256:stop"))).await);
                let out = handle_sign(&keys, &guard, &sign[1..], None, &conn).await;
                assert_eq!(out, vec![SSH_AGENT_FAILURE]);
            }
        }

        /// A stop that lands while the request waits for the user: the
        /// approval that was about to be given signs nothing.
        #[tokio::test]
        async fn a_stop_during_the_confirmation_signs_nothing() {
            let (keys, sign) = store_with_a_key();
            let asked = Arc::new(tokio::sync::Notify::new());
            let confirm: ConfirmFn = {
                let asked = asked.clone();
                Arc::new(move |_req: SignRequest| {
                    let asked = asked.clone();
                    Box::pin(async move {
                        asked.notify_one();
                        std::future::pending::<bool>().await
                    })
                })
            };
            let guard = SignGuard::new(SignPolicy::Always, Some(confirm));
            let request = tokio::spawn({
                let (keys, guard) = (keys.clone(), guard.clone());
                async move {
                    let mut conn = ConnState::default();
                    process_message(&sign, &keys, &guard, None, &mut conn).await
                }
            });
            asked.notified().await;
            guard.cancel();
            assert_eq!(request.await.unwrap(), vec![SSH_AGENT_FAILURE]);
        }

        /// The connection itself ends with the agent, in every transport:
        /// the client reads end-of-file, as from an agent that exited.
        #[tokio::test]
        async fn a_connection_ends_when_the_agent_stops() {
            let (keys, sign) = store_with_a_key();
            let guard = SignGuard::new(SignPolicy::Never, None);
            let (mut client, server) = tokio::io::duplex(4096);
            let served = tokio::spawn(serve(server, keys, guard.clone(), None));

            client.write_u32(1).await.unwrap();
            client
                .write_u8(SSH_AGENTC_REQUEST_IDENTITIES)
                .await
                .unwrap();
            let len = client.read_u32().await.unwrap() as usize;
            let mut answer = vec![0u8; len];
            client.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer[0], SSH_AGENT_IDENTITIES_ANSWER);

            guard.cancel();
            served.await.unwrap().unwrap();

            // Whatever the client still sends, nothing comes back.
            let _ = client.write_u32(sign.len() as u32).await;
            let _ = client.write_all(&sign).await;
            let mut rest = Vec::new();
            let _ = client.read_to_end(&mut rest).await;
            assert!(rest.is_empty(), "answered after the stop: {rest:?}");
        }

        /// A connection opened after the stop (a transport slow to notice)
        /// is closed at once.
        #[tokio::test]
        async fn serving_on_a_stopped_agent_closes_at_once() {
            let (keys, _) = store_with_a_key();
            let guard = SignGuard::new(SignPolicy::Never, None);
            guard.cancel();
            let (mut client, server) = tokio::io::duplex(4096);
            serve(server, keys, guard, None).await.unwrap();
            let mut rest = Vec::new();
            let _ = client.read_to_end(&mut rest).await;
            assert!(rest.is_empty());
        }

        /// RFC 8032 §7.1 "TEST 2" Ed25519 vector. Pins the two things a
        /// `ed25519-dalek` major bump could silently change under us: that
        /// `SigningKey::from_bytes` reads its input as the 32-byte *seed*
        /// (not an expanded secret scalar), and that the signature we put on
        /// the wire is the standard 64-byte R‖S encoding. Both are wrong-but-
        /// compiling failure modes — every SSH auth would break with no type
        /// error to catch it.
        #[test]
        fn handle_sign_matches_rfc8032_ed25519_vector() {
            use tokio::runtime::Runtime;

            fn unhex(s: &str) -> Vec<u8> {
                (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                    .collect()
            }

            let seed: [u8; 32] =
                unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                    .try_into()
                    .unwrap();
            let expected_public =
                unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
            let message = unhex("72");
            let expected_sig = unhex(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                 085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            );

            let signer = SigningKey::from_bytes(&seed);
            assert_eq!(
                signer.verifying_key().to_bytes().as_slice(),
                expected_public,
                "seed did not derive the RFC 8032 public key"
            );

            let pub_blob = b"rfc8032-test-2".to_vec();
            let keys: KeyStore = Arc::new(Mutex::new(vec![AgentKey {
                pub_blob: pub_blob.clone(),
                comment: "rfc8032".into(),
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:test".into(),
                kind: SignerKind::Ed25519(signer),
            }]));

            let mut payload = Vec::new();
            write_string(&mut payload, &pub_blob);
            write_string(&mut payload, &message);
            payload.extend_from_slice(&u32::to_be_bytes(0)); // flags

            let rt = Runtime::new().unwrap();
            let guard = SignGuard::new(SignPolicy::Never, None);
            let out = rt.block_on(handle_sign(
                &keys,
                &guard,
                &payload,
                None,
                &ConnState::default(),
            ));

            assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);
            let mut reader = SshReader::new(&out[1..]);
            let sig_blob = reader.read_string().unwrap();

            let mut inner = SshReader::new(sig_blob);
            assert_eq!(inner.read_string().unwrap(), b"ssh-ed25519");
            assert_eq!(inner.read_string().unwrap(), expected_sig.as_slice());
        }

        // ---- ECDSA -------------------------------------------------------

        fn sign_with(keys: &KeyStore, pub_blob: &[u8], data: &[u8], conn: &ConnState) -> Vec<u8> {
            let mut payload = Vec::new();
            write_string(&mut payload, pub_blob);
            write_string(&mut payload, data);
            payload.extend_from_slice(&u32::to_be_bytes(0));
            let guard = SignGuard::new(SignPolicy::Never, None);
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(handle_sign(keys, &guard, &payload, None, conn))
        }

        /// Every NIST curve OpenSSH generates must load and produce a
        /// signature that verifies against the key's public half, with the
        /// algorithm name ssh expects. A verification against the public
        /// key (not a byte comparison) is the right oracle here: ECDSA
        /// signatures are not reproducible byte for byte.
        #[test]
        fn ecdsa_keys_load_and_sign_verifiably_on_every_curve() {
            use rsa::signature::Verifier;
            for (pem, algo) in [
                (
                    include_str!("../tests/fixtures/ssh/ecdsa-p256"),
                    "ecdsa-sha2-nistp256",
                ),
                (
                    include_str!("../tests/fixtures/ssh/ecdsa-p384"),
                    "ecdsa-sha2-nistp384",
                ),
                (
                    include_str!("../tests/fixtures/ssh/ecdsa-p521"),
                    "ecdsa-sha2-nistp521",
                ),
            ] {
                let key = try_load_agent_key(pem, "fallback")
                    .unwrap()
                    .expect("ECDSA must no longer be skipped");
                assert_eq!(key.algorithm, algo);
                assert!(key.comment.starts_with("clavix-test-p"));
                let pub_blob = key.pub_blob.clone();
                let keys: KeyStore = Arc::new(Mutex::new(vec![key]));

                let out = sign_with(&keys, &pub_blob, b"challenge", &ConnState::default());
                assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE, "{algo}");
                let sig_blob = SshReader::new(&out[1..]).read_string().unwrap();
                assert_eq!(
                    SshReader::new(sig_blob).read_string().unwrap(),
                    algo.as_bytes()
                );

                let public = ssh_key::PublicKey::from_bytes(&pub_blob).unwrap();
                let sig = ssh_key::Signature::try_from(sig_blob).unwrap();
                Verifier::verify(&public, b"challenge", &sig).expect(algo);
                assert!(
                    Verifier::verify(&public, b"something else", &sig).is_err(),
                    "{algo}: signature must be bound to the data"
                );
            }
        }

        /// Known-answer test: RFC 6979 appendix A.2.5 (P-256, SHA-256,
        /// message "sample"). `ssh-key` signs ECDSA deterministically, so
        /// the agent's answer must be exactly the RFC's `(r, s)`. Run it
        /// on any `ssh-key` / `p256` / `ecdsa` bump: a verifying-but-wrong
        /// nonce derivation would still pass the round-trip test above.
        #[test]
        fn ecdsa_p256_matches_rfc6979_vector() {
            fn unhex(s: &str) -> Vec<u8> {
                (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                    .collect()
            }
            let x = unhex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
            let secret = p256::SecretKey::from_slice(&x).unwrap();
            let keypair = ssh_key::private::EcdsaKeypair::NistP256 {
                public: secret.public_key().into(),
                private: secret.into(),
            };
            let pk = PrivateKey::from(keypair);
            let pub_blob = pk.public_key().to_bytes().unwrap();
            let keys: KeyStore = Arc::new(Mutex::new(vec![AgentKey {
                pub_blob: pub_blob.clone(),
                comment: "rfc6979".into(),
                algorithm: "ecdsa-sha2-nistp256".into(),
                fingerprint: "SHA256:rfc6979".into(),
                kind: SignerKind::Ecdsa(Box::new(pk)),
            }]));

            let out = sign_with(&keys, &pub_blob, b"sample", &ConnState::default());
            assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);
            let sig_blob = SshReader::new(&out[1..]).read_string().unwrap();
            let mut sig = SshReader::new(sig_blob);
            assert_eq!(sig.read_string().unwrap(), b"ecdsa-sha2-nistp256");
            // RFC 5656: the signature is `mpint r, mpint s`; an mpint
            // with its top bit set carries a leading zero byte.
            let mut rs = SshReader::new(sig.read_string().unwrap());
            let strip = |m: &[u8]| m.strip_prefix(&[0]).unwrap_or(m).to_vec();
            let r = strip(rs.read_string().unwrap());
            let s = strip(rs.read_string().unwrap());
            assert!(rs.is_empty());
            assert_eq!(
                r,
                unhex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716")
            );
            assert_eq!(
                s,
                unhex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
            );
        }

        // ---- session-bind@openssh.com ------------------------------------

        /// A fake server host key (Ed25519, fixed seed) able to sign
        /// session identifiers the way sshd does during key exchange.
        struct HostKey(SigningKey);

        impl HostKey {
            fn new(seed: u8) -> Self {
                Self(SigningKey::from_bytes(&[seed; 32]))
            }
            fn blob(&self) -> Vec<u8> {
                let mut b = Vec::new();
                write_string(&mut b, b"ssh-ed25519");
                write_string(&mut b, self.0.verifying_key().as_bytes());
                b
            }
            fn sign(&self, sid: &[u8]) -> Vec<u8> {
                let mut b = Vec::new();
                write_string(&mut b, b"ssh-ed25519");
                write_string(&mut b, &self.0.sign(sid).to_bytes());
                b
            }
        }

        fn bind_msg(host_blob: &[u8], sid: &[u8], sig: &[u8], forwarded: bool) -> Vec<u8> {
            let mut m = vec![SSH_AGENTC_EXTENSION];
            write_string(&mut m, EXT_SESSION_BIND);
            write_string(&mut m, host_blob);
            write_string(&mut m, sid);
            write_string(&mut m, sig);
            m.push(forwarded as u8);
            m
        }

        fn bind(conn: &mut ConnState, host: &HostKey, sid: &[u8], forwarded: bool) -> Vec<u8> {
            let msg = bind_msg(&host.blob(), sid, &host.sign(sid), forwarded);
            run(&msg, conn)
        }

        fn run(msg: &[u8], conn: &mut ConnState) -> Vec<u8> {
            let keys: KeyStore = Arc::new(Mutex::new(Vec::new()));
            let guard = SignGuard::new(SignPolicy::Never, None);
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(process_message(msg, &keys, &guard, None, conn))
        }

        fn userauth(sid: &[u8], hostbound: Option<&[u8]>) -> Vec<u8> {
            let mut d = Vec::new();
            write_string(&mut d, sid);
            d.push(SSH_MSG_USERAUTH_REQUEST);
            write_string(&mut d, b"git");
            write_string(&mut d, b"ssh-connection");
            match hostbound {
                Some(_) => write_string(&mut d, b"publickey-hostbound-v00@openssh.com"),
                None => write_string(&mut d, b"publickey"),
            }
            d.push(1);
            write_string(&mut d, b"ssh-ed25519");
            write_string(&mut d, b"client-key-blob");
            if let Some(hk) = hostbound {
                write_string(&mut d, hk);
            }
            d
        }

        #[test]
        fn session_bind_records_a_verified_binding() {
            let host = HostKey::new(7);
            let mut conn = ConnState::default();
            assert_eq!(
                bind(&mut conn, &host, b"sid-1", false),
                vec![SSH_AGENT_SUCCESS]
            );
            assert_eq!(conn.hops.len(), 1);
            let hop = &conn.hops[0];
            assert_eq!(hop.key_blob, host.blob());
            assert!(!hop.forwarded);
            assert!(hop.fingerprint.starts_with("SHA256:"));
        }

        #[test]
        fn session_bind_rejects_a_signature_from_another_key() {
            let (host, impostor) = (HostKey::new(7), HostKey::new(8));
            let mut conn = ConnState::default();
            let msg = bind_msg(&host.blob(), b"sid-1", &impostor.sign(b"sid-1"), false);
            assert_eq!(run(&msg, &mut conn), vec![SSH_AGENT_FAILURE]);
            // Signed by the right key but over another session id.
            let msg = bind_msg(&host.blob(), b"sid-1", &host.sign(b"sid-2"), false);
            assert_eq!(run(&msg, &mut conn), vec![SSH_AGENT_FAILURE]);
            assert!(conn.hops.is_empty());
        }

        #[test]
        fn session_bind_rejects_malformed_bodies() {
            let host = HostKey::new(7);
            let mut conn = ConnState::default();
            let mut msg = bind_msg(&host.blob(), b"sid", &host.sign(b"sid"), false);
            msg.push(0); // trailing garbage
            assert_eq!(run(&msg, &mut conn), vec![SSH_AGENT_FAILURE]);
            let mut msg = bind_msg(&host.blob(), b"sid", &host.sign(b"sid"), false);
            *msg.last_mut().unwrap() = 2; // not a boolean
            assert_eq!(run(&msg, &mut conn), vec![SSH_AGENT_FAILURE]);
            let msg = bind_msg(&host.blob(), b"sid", &host.sign(b"sid"), false);
            assert_eq!(
                run(&msg[..msg.len() - 1], &mut conn),
                vec![SSH_AGENT_FAILURE]
            );
            assert!(conn.hops.is_empty());
        }

        #[test]
        fn unknown_extensions_fail() {
            let mut m = vec![SSH_AGENTC_EXTENSION];
            write_string(&mut m, b"query");
            assert_eq!(run(&m, &mut ConnState::default()), vec![SSH_AGENT_FAILURE]);
        }

        #[test]
        fn forwarding_chain_is_recorded_outermost_first() {
            let (jump, dest) = (HostKey::new(1), HostKey::new(2));
            let mut conn = ConnState::default();
            assert_eq!(
                bind(&mut conn, &jump, b"sid-jump", true),
                vec![SSH_AGENT_SUCCESS]
            );
            // OpenSSH re-sends the forwarding bind per channel: idempotent.
            assert_eq!(
                bind(&mut conn, &jump, b"sid-jump", true),
                vec![SSH_AGENT_SUCCESS]
            );
            assert_eq!(
                bind(&mut conn, &dest, b"sid-dest", false),
                vec![SSH_AGENT_SUCCESS]
            );
            let shape: Vec<_> = conn
                .hops
                .iter()
                .map(|h| (h.key_blob.clone(), h.forwarded))
                .collect();
            assert_eq!(shape, vec![(jump.blob(), true), (dest.blob(), false)]);
        }

        #[test]
        fn same_session_with_another_host_key_is_refused() {
            let (a, b) = (HostKey::new(1), HostKey::new(2));
            let mut conn = ConnState::default();
            assert_eq!(bind(&mut conn, &a, b"sid", true), vec![SSH_AGENT_SUCCESS]);
            assert_eq!(bind(&mut conn, &b, b"sid", true), vec![SSH_AGENT_FAILURE]);
            assert_eq!(conn.hops.len(), 1);
        }

        #[test]
        fn a_connection_bound_for_auth_accepts_no_further_binding() {
            let (a, b) = (HostKey::new(1), HostKey::new(2));
            let mut conn = ConnState::default();
            assert_eq!(
                bind(&mut conn, &a, b"sid-a", false),
                vec![SSH_AGENT_SUCCESS]
            );
            assert_eq!(bind(&mut conn, &b, b"sid-b", true), vec![SSH_AGENT_FAILURE]);
            assert_eq!(conn.hops.len(), 1);
        }

        #[test]
        fn binding_count_is_capped() {
            let host = HostKey::new(3);
            let mut conn = ConnState::default();
            for i in 0..MAX_SESSION_BINDS {
                let sid = format!("sid-{i}");
                assert_eq!(
                    bind(&mut conn, &host, sid.as_bytes(), true),
                    vec![SSH_AGENT_SUCCESS]
                );
            }
            assert_eq!(
                bind(&mut conn, &host, b"one-too-many", true),
                vec![SSH_AGENT_FAILURE]
            );
        }

        fn ed25519_store() -> (KeyStore, Vec<u8>) {
            let pub_blob = b"client-key-blob".to_vec();
            let keys = Arc::new(Mutex::new(vec![AgentKey {
                pub_blob: pub_blob.clone(),
                comment: "c".into(),
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:c".into(),
                kind: SignerKind::Ed25519(SigningKey::from_bytes(&[9; 32])),
            }]));
            (keys, pub_blob)
        }

        #[test]
        fn auth_bound_connection_only_signs_its_own_session() {
            let host = HostKey::new(4);
            let mut conn = ConnState::default();
            bind(&mut conn, &host, b"sid-ok", false);
            let (keys, blob) = ed25519_store();

            let ok = sign_with(&keys, &blob, &userauth(b"sid-ok", None), &conn);
            assert_eq!(ok[0], SSH_AGENT_SIGN_RESPONSE);
            let relayed = sign_with(&keys, &blob, &userauth(b"sid-other", None), &conn);
            assert_eq!(relayed, vec![SSH_AGENT_FAILURE]);

            // Host-bound variant: the named host key must be the bound one.
            let ok = sign_with(
                &keys,
                &blob,
                &userauth(b"sid-ok", Some(&host.blob())),
                &conn,
            );
            assert_eq!(ok[0], SSH_AGENT_SIGN_RESPONSE);
            let wrong = HostKey::new(5).blob();
            let bad = sign_with(&keys, &blob, &userauth(b"sid-ok", Some(&wrong)), &conn);
            assert_eq!(bad, vec![SSH_AGENT_FAILURE]);

            // Data that is not a user-auth request (e.g. SSHSIG for git
            // commit signing) is not subject to the session check.
            let other = sign_with(&keys, &blob, b"SSHSIG\0\0\0\x01", &conn);
            assert_eq!(other[0], SSH_AGENT_SIGN_RESPONSE);
        }

        #[test]
        fn forwarded_binding_does_not_restrict_the_session() {
            // The last hop being a forwarding bind means "a process on that
            // host is using the forwarded agent" — its own sessions are
            // unknown to us, so the session check must not fire.
            let host = HostKey::new(6);
            let mut conn = ConnState::default();
            bind(&mut conn, &host, b"sid-fwd", true);
            let (keys, blob) = ed25519_store();
            let out = sign_with(&keys, &blob, &userauth(b"sid-elsewhere", None), &conn);
            assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);
        }

        #[test]
        fn parse_userauth_request_accepts_only_publickey_requests() {
            assert_eq!(
                parse_userauth_request(&userauth(b"s", None)),
                Some((&b"s"[..], None))
            );
            let hb = userauth(b"s", Some(b"hk"));
            assert_eq!(
                parse_userauth_request(&hb),
                Some((&b"s"[..], Some(&b"hk"[..])))
            );
            let mut trailing = userauth(b"s", None);
            trailing.push(0);
            assert_eq!(parse_userauth_request(&trailing), None);
            assert_eq!(parse_userauth_request(b"SSHSIG"), None);
            assert_eq!(parse_userauth_request(&[]), None);
        }

        #[test]
        fn confirmation_receives_the_bindings() {
            let seen: Arc<std::sync::Mutex<Vec<HostHop>>> = Arc::default();
            let seen2 = seen.clone();
            let seen_req: Arc<std::sync::Mutex<Option<SignRequest>>> = Arc::default();
            let seen_req2 = seen_req.clone();
            let confirm: ConfirmFn = Arc::new(move |req: SignRequest| {
                *seen2.lock().unwrap() = req.hops.clone();
                *seen_req2.lock().unwrap() = Some(req);
                Box::pin(async { true })
            });
            let guard = SignGuard::new(SignPolicy::Always, Some(confirm));
            let (jump, dest) = (HostKey::new(1), HostKey::new(2));
            let mut conn = ConnState::default();
            bind(&mut conn, &jump, b"sid-j", true);
            bind(&mut conn, &dest, b"sid-d", false);
            let (keys, blob) = ed25519_store();

            let mut payload = Vec::new();
            write_string(&mut payload, &blob);
            write_string(&mut payload, &userauth(b"sid-d", None));
            payload.extend_from_slice(&u32::to_be_bytes(0));
            let out = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(handle_sign(&keys, &guard, &payload, None, &conn));
            assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);
            assert_eq!(*seen.lock().unwrap(), conn.hops);

            // Everything a phone needs to re-verify the request on its own.
            let req = seen_req.lock().unwrap().take().unwrap();
            assert_eq!(req.key_blob, blob);
            assert_eq!(req.data, userauth(b"sid-d", None));
            assert!(req.hops.iter().all(|h| !h.signature.is_empty()));
            assert!(req.phone_eligible());
        }

        #[test]
        fn phone_eligible_only_for_a_bound_userauth_request() {
            let (jump, dest) = (HostKey::new(1), HostKey::new(2));
            let mut auth = ConnState::default();
            bind(&mut auth, &dest, b"sid-d", false);
            let mut fwd_only = ConnState::default();
            bind(&mut fwd_only, &jump, b"sid-j", true);
            let req = |data: Vec<u8>, hops: &[HostHop]| SignRequest {
                hops: hops.to_vec(),
                data,
                ..req_for(&dummy_key("SHA256:a"))
            };

            assert!(req(userauth(b"sid-d", None), &auth.hops).phone_eligible());
            // git commit signing: not a user-auth request.
            assert!(!req(b"SSHSIG-ish data".to_vec(), &auth.hops).phone_eligible());
            // a client that doesn't bind.
            assert!(!req(userauth(b"sid-d", None), &[]).phone_eligible());
            // only a forwarding bind: the destination is unknown.
            assert!(!req(userauth(b"sid-j", None), &fwd_only.hops).phone_eligible());
            // another session than the bound one.
            assert!(!req(userauth(b"sid-x", None), &auth.hops).phone_eligible());
        }

        // ---- phone-held keys (sign mode, vault locked) ----------------------

        /// What the fake phone does with a request.
        #[derive(Clone, Copy)]
        enum PhoneAnswer {
            Sign,
            Deny,
            /// A signature by another key: must not reach the client.
            WrongSignature,
        }

        /// A phone holding an Ed25519 key (fixed seed), answering `answer`
        /// once `gate` is opened (at once without a gate).
        struct FakePhone {
            seed: u8,
            answer: PhoneAnswer,
            gate: Option<Arc<tokio::sync::Notify>>,
            seen: Arc<std::sync::Mutex<Vec<SignRequest>>>,
        }

        impl FakePhone {
            fn new(answer: PhoneAnswer) -> Self {
                Self {
                    seed: 21,
                    answer,
                    gate: None,
                    seen: Arc::default(),
                }
            }
            fn blob(&self) -> Vec<u8> {
                HostKey::new(self.seed).blob()
            }
        }

        impl PhoneSigner for FakePhone {
            fn sign(&self, req: SignRequest) -> PhoneSignFuture {
                let sig = match self.answer {
                    PhoneAnswer::Sign => Ok(HostKey::new(self.seed).sign(&req.data)),
                    PhoneAnswer::WrongSignature => Ok(HostKey::new(99).sign(&req.data)),
                    PhoneAnswer::Deny => Err("denied by the signer".to_string()),
                };
                self.seen.lock().unwrap().push(req);
                let gate = self.gate.clone();
                Box::pin(async move {
                    if let Some(gate) = gate {
                        gate.notified().await;
                    }
                    sig
                })
            }
        }

        fn phone_store(
            phone: FakePhone,
        ) -> (KeyStore, Vec<u8>, Arc<std::sync::Mutex<Vec<SignRequest>>>) {
            let blob = phone.blob();
            let seen = phone.seen.clone();
            let key = AgentKey::phone(blob.clone(), "iphone".into(), Arc::new(phone)).unwrap();
            assert_eq!(key.algorithm, "ssh-ed25519");
            assert!(key.fingerprint.starts_with("SHA256:"));
            (Arc::new(Mutex::new(vec![key])), blob, seen)
        }

        fn bound_to(host: &HostKey, sid: &[u8]) -> ConnState {
            let mut conn = ConnState::default();
            assert_eq!(bind(&mut conn, host, sid, false), vec![SSH_AGENT_SUCCESS]);
            conn
        }

        /// A phone that never answers, and says when its request is
        /// dropped (which is what withdraws it from the relay).
        struct SilentPhone {
            asked: Arc<tokio::sync::Notify>,
            dropped: Arc<std::sync::atomic::AtomicBool>,
        }

        struct OnDrop(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        impl PhoneSigner for SilentPhone {
            fn sign(&self, _req: SignRequest) -> PhoneSignFuture {
                let (asked, dropped) = (self.asked.clone(), OnDrop(self.dropped.clone()));
                Box::pin(async move {
                    let _dropped = dropped;
                    asked.notify_one();
                    std::future::pending().await
                })
            }
        }

        async fn send<S: AsyncWrite + Unpin>(stream: &mut S, msg: &[u8]) {
            stream.write_u32(msg.len() as u32).await.unwrap();
            stream.write_all(msg).await.unwrap();
        }

        async fn receive<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
            let len = stream.read_u32().await.unwrap() as usize;
            let mut answer = vec![0u8; len];
            stream.read_exact(&mut answer).await.unwrap();
            answer
        }

        fn sign_msg(pub_blob: &[u8], data: &[u8]) -> Vec<u8> {
            let mut m = vec![SSH_AGENTC_SIGN_REQUEST];
            write_string(&mut m, pub_blob);
            write_string(&mut m, data);
            m.extend_from_slice(&u32::to_be_bytes(0));
            m
        }

        /// `ssh` interrupted (Ctrl-C, its own timeout) while the phone is
        /// asked: the request is withdrawn, instead of staying on the
        /// phone for an approval that would sign for nobody.
        #[tokio::test]
        async fn a_client_that_leaves_withdraws_its_request_from_the_phone() {
            let host = HostKey::new(4);
            let asked = Arc::new(tokio::sync::Notify::new());
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let blob = HostKey::new(21).blob();
            let phone = SilentPhone {
                asked: asked.clone(),
                dropped: dropped.clone(),
            };
            let key = AgentKey::phone(blob.clone(), "iphone".into(), Arc::new(phone)).unwrap();
            let keys: KeyStore = Arc::new(Mutex::new(vec![key]));
            let guard = SignGuard::new(SignPolicy::Never, None);
            let (mut client, server) = tokio::io::duplex(4096);
            let served = tokio::spawn(serve(server, keys, guard, None));

            let sid = b"sid-gone";
            send(
                &mut client,
                &bind_msg(&host.blob(), sid, &host.sign(sid), false),
            )
            .await;
            assert_eq!(receive(&mut client).await, vec![SSH_AGENT_SUCCESS]);
            send(
                &mut client,
                &sign_msg(&blob, &userauth(sid, Some(&host.blob()))),
            )
            .await;
            asked.notified().await;
            assert!(!dropped.load(std::sync::atomic::Ordering::SeqCst));

            drop(client);
            // The connection ends by itself: the phone would never answer.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), served)
                .await
                .expect("the request outlived its client");
            assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        }

        /// Watching the socket during a request must not eat what the
        /// client sends meanwhile: a second request written before the
        /// first is answered is still answered, in order.
        #[tokio::test]
        async fn a_request_sent_before_the_previous_answer_is_still_served() {
            let host = HostKey::new(4);
            let gate = Arc::new(tokio::sync::Notify::new());
            let mut phone = FakePhone::new(PhoneAnswer::Sign);
            phone.gate = Some(gate.clone());
            let (keys, blob, seen) = phone_store(phone);
            let guard = SignGuard::new(SignPolicy::Never, None);
            let (mut client, server) = tokio::io::duplex(4096);
            let served = tokio::spawn(serve(server, keys, guard, None));

            let sid = b"sid-two";
            send(
                &mut client,
                &bind_msg(&host.blob(), sid, &host.sign(sid), false),
            )
            .await;
            assert_eq!(receive(&mut client).await, vec![SSH_AGENT_SUCCESS]);
            let data = userauth(sid, Some(&host.blob()));
            send(&mut client, &sign_msg(&blob, &data)).await;
            // Sent while the phone is being asked, in two pieces.
            client.write_all(&[0, 0]).await.unwrap();
            while seen.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
            client
                .write_all(&[0, 1, SSH_AGENTC_REQUEST_IDENTITIES])
                .await
                .unwrap();
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
            gate.notify_one();

            let mut expected = vec![SSH_AGENT_SIGN_RESPONSE];
            write_string(&mut expected, &HostKey::new(21).sign(&data));
            assert_eq!(receive(&mut client).await, expected);
            assert_eq!(receive(&mut client).await[0], SSH_AGENT_IDENTITIES_ANSWER);

            drop(client);
            served.await.unwrap().unwrap();
        }

        #[test]
        fn phone_key_answers_with_the_phones_signature() {
            let host = HostKey::new(4);
            let conn = bound_to(&host, b"sid-ok");
            let (keys, blob, seen) = phone_store(FakePhone::new(PhoneAnswer::Sign));
            let data = userauth(b"sid-ok", Some(&host.blob()));

            let out = sign_with(&keys, &blob, &data, &conn);
            assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);
            let mut expected = vec![SSH_AGENT_SIGN_RESPONSE];
            write_string(&mut expected, &HostKey::new(21).sign(&data));
            assert_eq!(out, expected);

            // The phone got everything it needs to check the login itself.
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].key_blob, blob);
            assert_eq!(seen[0].data, data);
            assert_eq!(seen[0].hops, conn.hops);
            assert_eq!(seen[0].key.comment, "iphone");
        }

        #[test]
        fn phone_key_denied_on_the_phone_fails() {
            let host = HostKey::new(4);
            let conn = bound_to(&host, b"sid-ok");
            let (keys, blob, seen) = phone_store(FakePhone::new(PhoneAnswer::Deny));
            let out = sign_with(&keys, &blob, &userauth(b"sid-ok", None), &conn);
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);
            assert_eq!(seen.lock().unwrap().len(), 1);
        }

        #[test]
        fn phone_key_signature_that_does_not_verify_is_dropped() {
            let host = HostKey::new(4);
            let conn = bound_to(&host, b"sid-ok");
            let (keys, blob, _) = phone_store(FakePhone::new(PhoneAnswer::WrongSignature));
            let out = sign_with(&keys, &blob, &userauth(b"sid-ok", None), &conn);
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);
        }

        #[test]
        fn phone_key_refuses_unbound_connections_without_asking() {
            let (keys, blob, seen) = phone_store(FakePhone::new(PhoneAnswer::Sign));
            let (jump, dest) = (HostKey::new(1), HostKey::new(2));

            // No session-bind at all (old OpenSSH, PuTTY…).
            let out = sign_with(&keys, &blob, &userauth(b"sid", None), &ConnState::default());
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);

            // Only a forwarding bind: the destination is unknown.
            let mut fwd = ConnState::default();
            bind(&mut fwd, &jump, b"sid-j", true);
            let out = sign_with(&keys, &blob, &userauth(b"sid-x", None), &fwd);
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);

            // Bound, but git commit signing: nothing the phone can check.
            let conn = bound_to(&dest, b"sid-d");
            let out = sign_with(&keys, &blob, b"SSHSIG\0\0\0\x01", &conn);
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);

            // Bound, but another session's challenge.
            let out = sign_with(&keys, &blob, &userauth(b"sid-other", None), &conn);
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);

            assert!(seen.lock().unwrap().is_empty(), "the phone was never asked");
        }

        #[test]
        fn phone_key_does_not_hold_the_key_store_while_the_phone_decides() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let host = HostKey::new(4);
            let conn = bound_to(&host, b"sid-ok");
            let gate = Arc::new(tokio::sync::Notify::new());
            let mut phone = FakePhone::new(PhoneAnswer::Sign);
            phone.gate = Some(gate.clone());
            let (keys, blob, seen) = phone_store(phone);
            let data = userauth(b"sid-ok", None);

            rt.block_on(async {
                let mut payload = Vec::new();
                write_string(&mut payload, &blob);
                write_string(&mut payload, &data);
                payload.extend_from_slice(&u32::to_be_bytes(0));
                let sign = tokio::spawn({
                    let keys = keys.clone();
                    async move {
                        let guard = SignGuard::new(SignPolicy::Never, None);
                        handle_sign(&keys, &guard, &payload, None, &conn).await
                    }
                });
                // Wait until the phone has the request, then list the keys
                // while it is still deciding: must not wait for it.
                while seen.lock().unwrap().is_empty() {
                    tokio::task::yield_now().await;
                }
                let list =
                    tokio::time::timeout(std::time::Duration::from_secs(5), handle_list(&keys))
                        .await
                        .expect("the key store must be free while the phone decides");
                assert_eq!(list[0], SSH_AGENT_IDENTITIES_ANSWER);
                assert!(!sign.is_finished());
                gate.notify_one();
                let out = sign.await.unwrap();
                assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);
            });
        }

        #[test]
        fn phone_key_rejects_a_blob_that_is_not_a_public_key() {
            let phone: Arc<dyn PhoneSigner> = Arc::new(FakePhone::new(PhoneAnswer::Sign));
            assert!(AgentKey::phone(b"garbage".to_vec(), "x".into(), phone).is_err());
        }
    }
} // mod proto

#[cfg(unix)]
mod unix {
    use std::path::PathBuf;
    use std::sync::Arc;

    use tokio::net::{UnixListener, UnixStream};
    use tokio::task::JoinHandle;

    use super::proto::{serve, AgentKey, CallerInfo, KeyInfo, KeyStore, SignGuard};
    use clavix_core::error::{Error, Result};

    pub struct SshAgentHandle {
        pub socket_path: PathBuf,
        /// Public-only summary of every key currently exposed by the agent.
        /// The signing material itself stays in the keystore guarded by the
        /// task; this list is safe to clone into a status response.
        pub keys: Vec<KeyInfo>,
        /// The accept loop. It owns the connection tasks (a `JoinSet`), so
        /// aborting it aborts every open connection with it.
        task: JoinHandle<()>,
        key_store: KeyStore,
        /// Used to deny parked confirmations on stop, so stopping never
        /// waits on a prompt nobody can answer, and to end the connections
        /// that are still open.
        guard: SignGuard,
    }

    impl SshAgentHandle {
        pub async fn stop(self) {
            self.end();
            let _ = tokio::fs::remove_file(&self.socket_path).await;
        }

        /// Non-async best-effort stop, suitable for `lock` / `logout` commands
        /// that don't want to be async just for this cleanup.
        pub fn stop_sync(self) {
            self.end();
            let _ = std::fs::remove_file(&self.socket_path);
        }

        /// Stop serving, on the listening socket and on every connection
        /// already open, and let go of the keys. A stop is what a vault
        /// lock does to the agent: after it, no client may list or use a
        /// key, however long ago it connected.
        ///
        /// Three layers, each enough on its own: the cancelled guard makes
        /// every request fail and every connection close; aborting the
        /// accept loop drops its `JoinSet`, which aborts the connection
        /// tasks; and the store is emptied so the key material goes now
        /// rather than when the last task is reaped.
        fn end(&self) {
            self.guard.cancel();
            self.task.abort();
            // Held only for the length of a lookup or of one signature.
            // If it is held right now, that task sees the cancelled guard
            // next and drops its clone of the store when it ends.
            if let Ok(mut keys) = self.key_store.try_lock() {
                keys.clear();
            }
        }
    }

    pub fn default_socket_path() -> Result<PathBuf> {
        let dir = dirs::runtime_dir()
            .or_else(dirs::cache_dir)
            .ok_or_else(|| Error::Storage {
                reason: "no runtime or cache dir available for agent socket".into(),
            })?;
        let mut path = dir;
        path.push("clavix");
        std::fs::create_dir_all(&path).map_err(|e| Error::Storage {
            reason: format!("cannot create agent dir {}: {e}", path.display()),
        })?;
        make_private(&path, 0o700)?;
        path.push("agent.sock");
        Ok(path)
    }

    /// Restrict `path` to its owner, and fail if that cannot be done.
    ///
    /// The directory is what keeps other users away from the socket:
    /// `bind` creates it with the umask's bits, and it only becomes 0600 a
    /// moment later. Inside a 0700 directory that moment does not matter.
    /// It matters outside `$XDG_RUNTIME_DIR` (which is already private):
    /// the fallback is the cache directory, always the case on macOS. A
    /// failure used to be ignored, leaving the agent reachable with
    /// whatever permissions happened to be there.
    fn make_private(path: &std::path::Path, mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
            Error::Storage {
                reason: format!("cannot restrict {} to its owner: {e}", path.display()),
            }
        })
    }

    /// Whether a connecting process may use the agent: the user Clavix
    /// runs as, or root, which is the rule of OpenSSH's `ssh-agent` (root
    /// can reach the keys anyway, and `sudo` with a preserved
    /// `SSH_AUTH_SOCK` is a real use). The socket's permissions already
    /// say so; this is the same rule, enforced a second time on every
    /// connection in case they were changed under us.
    fn peer_allowed(peer_uid: u32, owner_uid: u32) -> bool {
        peer_uid == owner_uid || peer_uid == 0
    }

    /// Read the peer's credentials off an accepted connection.
    ///
    /// Returns `None` rather than failing the connection: an unidentifiable
    /// caller must still be able to request a signature (the user then sees
    /// "unknown", which is itself useful information).
    fn peer_caller(stream: &UnixStream) -> Option<CallerInfo> {
        let cred = stream.peer_cred().ok()?;
        // `pid()` is `Option` because not every Unix exposes it.
        let pid = cred.pid()?;
        if pid <= 0 {
            return None;
        }
        let pid = pid as u32;
        Some(CallerInfo {
            pid,
            name: process_name(pid),
        })
    }

    /// Resolve a pid to a process name. Linux-only via `/proc`; other Unixes
    /// get `None` and the prompt falls back to showing the bare pid.
    fn process_name(pid: u32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
            // `comm` is attacker-controlled text heading for a dialog.
            super::proto::sanitize_process_label(comm.trim())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            None
        }
    }

    pub async fn start_agent(
        socket_path: PathBuf,
        keys: Vec<AgentKey>,
        guard: SignGuard,
    ) -> Result<SshAgentHandle> {
        // Remove any stale socket file.
        let _ = tokio::fs::remove_file(&socket_path).await;
        let listener = UnixListener::bind(&socket_path).map_err(|e| Error::Storage {
            reason: format!("bind {}: {e}", socket_path.display()),
        })?;
        // An agent that cannot make its socket private does not serve.
        // The socket's owner is the user Clavix runs as: the uid every
        // peer is compared with.
        let owner_uid = make_private(&socket_path, 0o600)
            .and_then(|()| {
                use std::os::unix::fs::MetadataExt;
                std::fs::metadata(&socket_path)
                    .map(|m| m.uid())
                    .map_err(|e| Error::Storage {
                        reason: format!("stat {}: {e}", socket_path.display()),
                    })
            })
            .inspect_err(|_| {
                let _ = std::fs::remove_file(&socket_path);
            })?;

        let key_summaries: Vec<KeyInfo> = keys.iter().map(KeyInfo::from).collect();
        let store: KeyStore = Arc::new(tokio::sync::Mutex::new(keys));
        let store_task = store.clone();
        let path_for_task = socket_path.clone();
        let guard_for_handle = guard.clone();

        let task = tokio::spawn(async move {
            // The connections belong to the accept loop: when it is
            // aborted (the agent stops), the set is dropped and every
            // connection task is aborted with it. Detached tasks would
            // outlive the stop, each with its own clone of the key store.
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let accepted = tokio::select! {
                    accepted = listener.accept() => accepted,
                    // Reap finished connections so the set does not grow.
                    Some(_) = connections.join_next() => continue,
                };
                match accepted {
                    Ok((stream, _)) => {
                        // Unknown credentials are refused too: nothing
                        // then says the peer is this user.
                        let peer_uid = stream.peer_cred().ok().map(|c| c.uid());
                        if !peer_uid.is_some_and(|uid| peer_allowed(uid, owner_uid)) {
                            eprintln!(
                                "[clavix agent] connection refused: peer uid {peer_uid:?} is \
                                 not the user Clavix runs as"
                            );
                            continue;
                        }
                        let store = store_task.clone();
                        let guard = guard.clone();
                        // Resolve the peer at accept time: the pid is only
                        // guaranteed meaningful while the connection is
                        // open, and the process may exit mid-request.
                        let caller = peer_caller(&stream);
                        connections.spawn(async move {
                            if let Err(e) = serve(stream, store, guard, caller).await {
                                eprintln!("[clavix agent] connection error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!(
                            "[clavix agent] accept failed on {}: {e}",
                            path_for_task.display()
                        );
                        break;
                    }
                }
            }
        });

        Ok(SshAgentHandle {
            socket_path,
            keys: key_summaries,
            task,
            key_store: store,
            guard: guard_for_handle,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Both ends of a socketpair live in this test process, so the
        /// credentials the agent reads must resolve to our own pid — which
        /// makes the expected value exactly known rather than "some pid".
        #[cfg(target_os = "linux")]
        #[test]
        fn peer_caller_resolves_the_connecting_process() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let dir = std::env::temp_dir().join(format!("clavix-peer-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let sock = dir.join("agent.sock");

            let caller = rt.block_on(async {
                let listener = UnixListener::bind(&sock).unwrap();
                let connect = tokio::spawn({
                    let sock = sock.clone();
                    async move { UnixStream::connect(&sock).await.unwrap() }
                });
                let (server_side, _) = listener.accept().await.unwrap();
                let _client = connect.await.unwrap();
                peer_caller(&server_side)
            });

            let caller = caller.expect("peer credentials available on Linux");
            assert_eq!(caller.pid, std::process::id());
            // The name comes from /proc/<pid>/comm — the test binary's own.
            let name = caller.name.expect("comm readable for a live process");
            assert!(!name.is_empty());
            assert!(!name.contains('\n'), "name must be a single line: {name:?}");

            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A pid that cannot exist yields no name rather than a bogus one.
        #[cfg(target_os = "linux")]
        #[test]
        fn process_name_is_none_for_an_unknown_pid() {
            assert_eq!(process_name(u32::MAX), None);
        }

        #[test]
        fn only_the_owner_and_root_may_use_the_agent() {
            assert!(peer_allowed(1000, 1000));
            assert!(peer_allowed(0, 1000));
            assert!(!peer_allowed(1001, 1000));
            assert!(!peer_allowed(65534, 1000));
        }

        /// The socket is 0600 once the agent runs, and an agent that
        /// cannot have a private socket does not start.
        #[tokio::test]
        async fn the_agent_socket_is_private_or_the_agent_does_not_start() {
            use super::super::proto::SignPolicy;
            use std::os::unix::fs::PermissionsExt;

            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("agent.sock");
            let guard = SignGuard::new(SignPolicy::Never, None);
            let handle = start_agent(socket.clone(), Vec::new(), guard.clone())
                .await
                .unwrap();
            let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            // Our own connections (same uid) are served.
            assert!(UnixStream::connect(&socket).await.is_ok());
            handle.stop().await;

            // Nowhere to bind: an error, not an agent.
            let missing = dir.path().join("missing").join("agent.sock");
            assert!(start_agent(missing, Vec::new(), guard).await.is_err());
            assert!(make_private(&dir.path().join("absent"), 0o700).is_err());
        }

        /// The scenario of the bug, on a real socket: a client connects
        /// while the vault is unlocked (think `ssh -A`, kept open for
        /// hours), the vault locks, then the client asks again. Under the
        /// silent policy it used to be served, with the vault's keys.
        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn a_connection_opened_before_the_stop_cannot_sign_after_it() {
            use super::super::proto::{SignPolicy, SignerKind};
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            const LIST: u8 = 11; // SSH_AGENTC_REQUEST_IDENTITIES
            const SIGN: u8 = 13; // SSH_AGENTC_SIGN_REQUEST
            const SIGN_RESPONSE: u8 = 14;

            async fn ask(client: &mut UnixStream, msg: &[u8]) -> std::io::Result<Vec<u8>> {
                client.write_u32(msg.len() as u32).await?;
                client.write_all(msg).await?;
                let len = client.read_u32().await? as usize;
                let mut answer = vec![0u8; len];
                client.read_exact(&mut answer).await?;
                Ok(answer)
            }

            for stop_sync in [true, false] {
                let dir = tempfile::tempdir().unwrap();
                let socket = dir.path().join("agent.sock");
                let blob = b"vault-key".to_vec();
                let key = AgentKey {
                    pub_blob: blob.clone(),
                    comment: "vault".into(),
                    algorithm: "ssh-ed25519".into(),
                    fingerprint: "SHA256:vault".into(),
                    kind: SignerKind::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])),
                };
                let guard = SignGuard::new(SignPolicy::Never, None);
                let handle = start_agent(socket.clone(), vec![key], guard).await.unwrap();
                let store = handle.key_store.clone();

                let mut sign = vec![SIGN];
                for field in [blob.as_slice(), b"data"] {
                    sign.extend_from_slice(&u32::to_be_bytes(field.len() as u32));
                    sign.extend_from_slice(field);
                }
                sign.extend_from_slice(&u32::to_be_bytes(0));

                // Unlocked: the connection works.
                let mut client = UnixStream::connect(&socket).await.unwrap();
                let listed = ask(&mut client, &[LIST]).await.unwrap();
                assert_eq!(&listed[1..5], &[0, 0, 0, 1]);
                let signed = ask(&mut client, &sign).await.unwrap();
                assert_eq!(signed[0], SIGN_RESPONSE);

                // The vault locks.
                if stop_sync {
                    handle.stop_sync();
                } else {
                    handle.stop().await;
                }

                // The same connection, afterwards: closed, no signature
                // and no key list.
                for msg in [sign.as_slice(), &[LIST]] {
                    match ask(&mut client, msg).await {
                        Err(_) => {}
                        Ok(answer) => panic!("answered after the stop: {answer:?}"),
                    }
                }
                assert!(store.lock().await.is_empty(), "keys kept after the stop");
                assert!(UnixStream::connect(&socket).await.is_err());
            }
        }
    }
} // mod unix

#[cfg(windows)]
mod windows {
    //! Windows endpoints for the agent: the OpenSSH named pipe
    //! (`\\.\pipe\openssh-ssh-agent`, used by ssh.exe / ssh-add /
    //! git-for-windows) and the PuTTY Pageant IPC window (`pageant`).

    use std::path::PathBuf;
    use std::sync::Arc;

    use tokio::net::windows::named_pipe::ServerOptions;
    use tokio::runtime::Runtime;
    use tokio::task::JoinHandle;

    use super::proto::{serve, AgentKey, CallerInfo, KeyInfo, KeyStore, SignGuard};
    use clavix_core::error::{Error, Result};

    /// How many accepts in a row may fail before the endpoint gives up.
    /// A single failure says nothing — a client can die between connect
    /// and handshake — but a run of them means the pipe itself is gone,
    /// and spinning on it forever would burn a core.
    const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 5;

    /// A stop still in flight looks exactly like a competing agent: the
    /// previous instance's handles are released by a background runtime
    /// shutdown, so they can outlive the call that replaces them by a few
    /// milliseconds. `start_agent` runs right after a stop whenever the
    /// confirmation policy changes, and blaming the Windows OpenSSH
    /// service for our own not-yet-closed handles would send the user
    /// looking in the wrong place. Retry quietly for up to a second first.
    const FIRST_INSTANCE_RETRIES: u32 = 20;
    const FIRST_INSTANCE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

    /// Test-only switch: create our own Pageant window even when an
    /// incumbent "Pageant" window exists. Production always yields to the
    /// incumbent (see `pageant::spawn_if_free`), but tests must be able to
    /// exercise our own window on machines where a Pageant-compatible
    /// agent (e.g. ssh-pageant) happens to be running.
    #[cfg(test)]
    pub static TEST_FORCE_PAGEANT: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    mod pageant {
        //! PuTTY Pageant IPC: a hidden top-level window whose class *and*
        //! title are `"Pageant"`, answering agent requests over the
        //! WM_COPYDATA + `PageantRequest%08x` shared-memory channel.
        //!
        //! Wire details (as implemented by PuTTY's winpgntc.c / pageant.c
        //! since 0.61; constants verified against upstream source):
        //!
        //! 1. Clients find us with `FindWindow("Pageant", "Pageant")`.
        //! 2. They create a file mapping named `PageantRequest%08x` (their
        //!    own thread id) and write the standard framed agent message —
        //!    the same 4-byte big-endian length + body used on sockets —
        //!    at offset 0 of the mapping.
        //! 3. They `SendMessage(hwnd, WM_COPYDATA, NULL, &cds)` with
        //!    `cds.dwData == 0x804e50ba` (AGENT_COPYDATA_ID) and
        //!    `cds.lpData` = the mapping name (length in `cbData`).
        //! 4. The agent opens the mapping, verifies its owner SID matches
        //!    the current user (PuTTY's cross-user guard — with signature
        //!    confirmations off it is the whole protection), processes the
        //!    request *synchronously* and writes the framed response back
        //!    at offset 0.
        //! 5. The window procedure returns non-zero on success, zero on
        //!    failure; the client is blocked on `SendMessage` either way.
        //!
        //! The sender is unknowable (wParam is NULL), so Pageant requests
        //! carry no caller identity for the confirmation prompt.
        //!
        //! The exchange is strictly synchronous — the answer must be in the
        //! mapping before the window procedure returns — so a signature
        //! confirmation parks this thread on the agent runtime, exactly as
        //! PuTTY's own modal confirmation blocks its message loop.

        use std::ffi::c_void;
        use std::sync::Arc;

        use tokio::runtime::Handle;
        use windows_sys::core::w;
        use windows_sys::Win32::Foundation::{
            CloseHandle, GetLastError, ERROR_CLASS_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER,
            HANDLE, HWND, LPARAM, LRESULT, WPARAM,
        };
        use windows_sys::Win32::Security::{PSID, TOKEN_QUERY};
        use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows_sys::Win32::System::Memory::{
            MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, VirtualQuery, FILE_MAP_ALL_ACCESS,
            FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_BASIC_INFORMATION,
        };
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, GetCurrentThreadId, OpenProcessToken,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, FindWindowW,
            GetMessageW, GetWindowLongPtrW, PostThreadMessageW, RegisterClassExW,
            SetWindowLongPtrW, TranslateMessage, CREATESTRUCTW, GWLP_USERDATA, MSG, WM_COPYDATA,
            WM_NCCREATE, WM_NCDESTROY, WM_QUIT, WNDCLASSEXW,
        };

        use super::super::proto::{
            process_message, ConnState, KeyStore, SignGuard, MAX_MESSAGE, SSH_AGENT_FAILURE,
        };

        /// Class and window name PuTTY clients search for. (`w!` yields
        /// the NUL-terminated wide pointer directly.)
        const CLASS_AND_TITLE: *const u16 = w!("Pageant");
        /// `dwData` marker of Pageant WM_COPYDATA messages (PuTTY's
        /// AGENT_COPYDATA_ID, "random goop" per their comment).
        const AGENT_COPYDATA_ID: usize = 0x804e50ba;
        /// Mapping names from real clients are always `PageantRequest` +
        /// hex thread id; requiring the prefix keeps a hostile caller from
        /// pointing us at arbitrary shared objects.
        const MAP_PREFIX: &[u8] = b"PageantRequest";
        const MAX_MAP_NAME: usize = 64;

        pub struct PageantThread {
            thread: std::thread::JoinHandle<()>,
            /// Needed to post WM_QUIT into the window thread's queue.
            thread_id: u32,
        }

        impl PageantThread {
            pub fn request_quit(&self) {
                unsafe {
                    PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0);
                }
            }

            pub fn join(self) {
                let _ = self.thread.join();
            }
        }

        enum PageantMsg {
            /// The window thread is alive; carries its id so `stop` can
            /// post WM_QUIT even while setup is still running.
            Started(u32),
            /// The hidden window exists — or setup failed, with the reason
            /// (the agent carries on with the pipe alone).
            Ready(Result<(), String>),
        }

        /// Where the last skipped endpoint left its reason, for the tests:
        /// a silently skipped endpoint is indistinguishable from a bug.
        #[cfg(test)]
        static LAST_UNAVAILABLE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

        /// The window handle the last run created, and where its message
        /// loop ended — test-only forensics for "the endpoint started but
        /// no window is findable".
        #[cfg(test)]
        static LAST_WINDOW: std::sync::Mutex<Option<isize>> = std::sync::Mutex::new(None);
        #[cfg(test)]
        static LAST_LOOP_EXIT: std::sync::Mutex<Option<(i32, u32)>> = std::sync::Mutex::new(None);

        /// The reason the most recent `spawn_if_free` returned `None`,
        /// when that was recorded (tests only).
        #[cfg(test)]
        pub fn user_sid_for_test() -> Option<Vec<u8>> {
            current_user_sid()
        }

        #[cfg(test)]
        pub fn last_unavailable_reason() -> Option<String> {
            LAST_UNAVAILABLE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        /// Forensics for a window that was created but cannot be found
        /// afterwards: handle, liveness, and — if alive — its parent,
        /// style, visibility and owning thread, plus how many same-named
        /// top-level windows `FindWindow` can see at all.
        #[cfg(test)]
        pub fn last_window_forensics() -> String {
            use std::cell::RefCell;
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                EnumWindows, GetClassNameW, GetParent, GetWindowLongPtrW, GetWindowTextW,
                GetWindowThreadProcessId, IsWindowVisible, GWL_STYLE,
            };

            let window = *LAST_WINDOW.lock().unwrap_or_else(|e| e.into_inner());
            let exit = *LAST_LOOP_EXIT.lock().unwrap_or_else(|e| e.into_inner());
            let Some(h) = window else {
                return format!("created=None, loop_exit={exit:?}");
            };

            thread_local! {
                /// Every top-level window the enumeration yields, as
                /// (hwnd, pid, class, title) — truncated in the report.
                static SEEN: RefCell<Vec<(isize, u32, String, String)>> =
                    const { RefCell::new(Vec::new()) };
            }

            unsafe extern "system" fn collect(hwnd: *mut std::ffi::c_void, _: isize) -> i32 {
                unsafe {
                    let mut class = [0u16; 64];
                    let n = GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32);
                    let mut title = [0u16; 64];
                    let m = GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32);
                    let mut pid = 0u32;
                    GetWindowThreadProcessId(hwnd, &mut pid);
                    SEEN.with(|seen| {
                        seen.borrow_mut().push((
                            hwnd as isize,
                            pid,
                            String::from_utf16_lossy(&class[..n.max(0) as usize]),
                            String::from_utf16_lossy(&title[..m.max(0) as usize]),
                        ))
                    });
                    1
                }
            }

            SEEN.with(|seen| seen.borrow_mut().clear());
            let enumerated = unsafe { EnumWindows(Some(collect), 0) };
            let enum_err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            let seen = SEEN.with(|seen| seen.borrow().clone());

            unsafe {
                let hwnd = h as HWND;
                let mut owner_tid = 0u32;
                GetWindowThreadProcessId(hwnd, &mut owner_tid);
                let own_seen = seen.iter().any(|(w, ..)| *w == h);
                let candidates: Vec<String> = seen
                    .iter()
                    .filter(|(w, _, class, title)| {
                        *w == h || class == "Pageant" || title == "Pageant"
                    })
                    .take(4)
                    .map(|(w, pid, class, title)| format!("{w:#x}/pid {pid}/{class}/{title}"))
                    .collect();
                format!(
                    "hwnd={h:#x} alive={} parent={:?} style={:#x} visible={} owner_tid={owner_tid} \
                     enum_ok={enumerated} enum_err={enum_err}, seen_total={}, own_seen={own_seen}, \
                     matching=[{}], loop_exit={exit:?}",
                    windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(hwnd) != 0,
                    GetParent(hwnd),
                    GetWindowLongPtrW(hwnd, GWL_STYLE),
                    IsWindowVisible(hwnd) != 0,
                    seen.len(),
                    candidates.join("; "),
                )
            }
        }

        /// The PuTTY endpoint is best-effort by design — the named pipe
        /// keeps serving without it — but skipping must never be silent:
        /// log the reason, and record it for the tests.
        fn unavailable(reason: String) -> Option<PageantThread> {
            eprintln!("[clavix agent] Pageant endpoint unavailable: {reason}");
            #[cfg(test)]
            {
                *LAST_UNAVAILABLE.lock().unwrap_or_else(|e| e.into_inner()) = Some(reason);
            }
            None
        }

        /// What the window procedure needs to answer a request.
        struct Ctx {
            keys: KeyStore,
            guard: SignGuard,
            rt: Handle,
        }

        /// Start the PuTTY endpoint — unless an incumbent `Pageant` window
        /// already exists (real Pageant, KeePassXC, another agent), in
        /// which case PuTTY clients would be served by *that* agent anyway
        /// and two windows would only split them unpredictably.
        pub fn spawn_if_free(
            keys: KeyStore,
            guard: SignGuard,
            rt: Handle,
        ) -> Option<PageantThread> {
            #[cfg(test)]
            {
                *LAST_UNAVAILABLE.lock().unwrap_or_else(|e| e.into_inner()) = None;
                *LAST_WINDOW.lock().unwrap_or_else(|e| e.into_inner()) = None;
                *LAST_LOOP_EXIT.lock().unwrap_or_else(|e| e.into_inner()) = None;
            }

            // Tests set this to exercise our own window even when a
            // Pageant-compatible agent (ssh-pageant, KeePassXC, PuTTY)
            // already owns the "Pageant" name on the machine — the
            // production path deliberately yields to that incumbent.
            #[cfg(test)]
            let force = super::TEST_FORCE_PAGEANT.load(std::sync::atomic::Ordering::Relaxed);
            #[cfg(not(test))]
            let force = false;

            if !force {
                unsafe {
                    let incumbent = FindWindowW(CLASS_AND_TITLE, CLASS_AND_TITLE);
                    if !incumbent.is_null() {
                        return unavailable(
                            "another Pageant window is already running; the OpenSSH \
                             named pipe still serves ssh.exe"
                                .into(),
                        );
                    }
                }
            }

            let ctx = Arc::new(Ctx { keys, guard, rt });
            let (tx, rx) = std::sync::mpsc::channel::<PageantMsg>();
            let thread = match std::thread::Builder::new()
                .name("clavix-pageant".into())
                .spawn(move || run_thread(ctx, tx))
            {
                Ok(t) => t,
                Err(e) => return unavailable(format!("cannot spawn the window thread: {e}")),
            };
            // The thread announces its id first, then whether the window
            // came up. A window that failed to appear means the endpoint
            // is dead before it served anything — report None (the thread
            // exits on its own).
            let thread_id = match rx.recv() {
                Ok(PageantMsg::Started(id)) => id,
                _ => return unavailable("window thread exited before announcing its id".into()),
            };
            match rx.recv() {
                Ok(PageantMsg::Ready(Ok(()))) => Some(PageantThread { thread, thread_id }),
                Ok(PageantMsg::Ready(Err(reason))) => unavailable(reason),
                _ => unavailable("window thread exited before reporting the window state".into()),
            }
        }

        fn run_thread(ctx: Arc<Ctx>, tx: std::sync::mpsc::Sender<PageantMsg>) {
            unsafe {
                // Announce before anything fallible: stop() may post
                // WM_QUIT from this moment on.
                let _ = tx.send(PageantMsg::Started(GetCurrentThreadId()));

                let hinst = GetModuleHandleW(std::ptr::null());
                if hinst.is_null() {
                    let _ = tx.send(PageantMsg::Ready(Err(format!(
                        "GetModuleHandleW failed (err {})",
                        GetLastError()
                    ))));
                    return;
                }

                // A previous agent run in this process may already have
                // registered the class; that registration is exactly what
                // we want, so ERROR_CLASS_ALREADY_EXISTS is not an error.
                let mut wc: WNDCLASSEXW = std::mem::zeroed();
                wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
                wc.lpfnWndProc = Some(pageant_wnd_proc);
                wc.hInstance = hinst;
                wc.lpszClassName = CLASS_AND_TITLE;
                let atom = RegisterClassExW(&wc);
                if atom == 0 {
                    let err = GetLastError();
                    if err != ERROR_CLASS_ALREADY_EXISTS {
                        let _ = tx.send(PageantMsg::Ready(Err(format!(
                            "RegisterClassExW failed (err {err})"
                        ))));
                        return;
                    }
                }

                // The window owns a Box<Arc<Ctx>> (freed on WM_NCDESTROY).
                let ctx_box = Box::new(ctx.clone());
                let hwnd = CreateWindowExW(
                    0,
                    CLASS_AND_TITLE,
                    CLASS_AND_TITLE,
                    0, // style 0: a bare hidden top-level window, never shown
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    hinst,
                    Box::into_raw(ctx_box) as *const c_void,
                );
                if hwnd.is_null() {
                    let _ = tx.send(PageantMsg::Ready(Err(format!(
                        "CreateWindowExW failed (err {})",
                        GetLastError()
                    ))));
                    return;
                }
                #[cfg(test)]
                {
                    *LAST_WINDOW.lock().unwrap_or_else(|e| e.into_inner()) = Some(hwnd as isize);
                }
                let _ = tx.send(PageantMsg::Ready(Ok(())));

                let mut msg: MSG = std::mem::zeroed();
                let mut rc;
                loop {
                    // 0 = WM_QUIT, -1 = error: leave the loop either way.
                    rc = GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0);
                    if rc <= 0 {
                        break;
                    }
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                #[cfg(test)]
                {
                    *LAST_LOOP_EXIT.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some((rc, GetLastError()));
                }
                let _ = DestroyWindow(hwnd);
            }
        }

        unsafe extern "system" fn pageant_wnd_proc(
            hwnd: HWND,
            msg: u32,
            wparam: WPARAM,
            lparam: LPARAM,
        ) -> LRESULT {
            match msg {
                WM_NCCREATE => {
                    // Stash the owning Arc (passed via CreateWindowExW's
                    // lpParam) in the window's user data; WM_NCDESTROY
                    // frees the box.
                    let create = lparam as *const CREATESTRUCTW;
                    if create.is_null() {
                        return 0;
                    }
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, (*create).lpCreateParams as isize);
                    // DefWindowProc must still see WM_NCCREATE: its handling
                    // is what actually *sets the window caption* from the
                    // CREATESTRUCT. A WndProc that swallows this message
                    // leaves the window nameless — `FindWindow("Pageant",
                    // "Pageant")` then never finds it, so no PuTTY client
                    // ever reaches us (measured: title length 0, not
                    // findable). The return value is still TRUE so the
                    // window is created.
                    DefWindowProcW(hwnd, msg, wparam, lparam);
                    1
                }
                WM_NCDESTROY => {
                    let p = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Arc<Ctx>;
                    if !p.is_null() {
                        drop(Box::from_raw(p));
                        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    }
                    DefWindowProcW(hwnd, msg, wparam, lparam)
                }
                WM_COPYDATA => handle_copydata(hwnd, lparam),
                _ => DefWindowProcW(hwnd, msg, wparam, lparam),
            }
        }

        /// A client is synchronously waiting for our answer, so any path
        /// that cannot produce one must return zero *now* rather than
        /// letting the send hang.
        unsafe fn handle_copydata(hwnd: HWND, lparam: LPARAM) -> LRESULT {
            let ctx_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const Arc<Ctx>;
            if ctx_ptr.is_null() {
                return 0;
            }
            let ctx = (*ctx_ptr).clone();

            let cds = lparam as *const COPYDATASTRUCT;
            if cds.is_null() {
                return 0;
            }
            let cds = &*cds;
            if cds.dwData != AGENT_COPYDATA_ID {
                return 0;
            }
            if cds.lpData.is_null() || cds.cbData == 0 || cds.cbData as usize > MAX_MAP_NAME {
                return 0;
            }

            // The mapping name is ASCII by construction ("PageantRequest" +
            // hex digits); check that and widen per byte, so no codepage
            // conversion ambiguity ever applies.
            let raw = std::slice::from_raw_parts(cds.lpData as *const u8, cds.cbData as usize);
            let raw = match raw.strip_suffix(&[0]) {
                Some(r) => r, // clients include the trailing NUL; tolerate
                None => raw,
            };
            if !raw.starts_with(MAP_PREFIX) || raw.len() == MAP_PREFIX.len() {
                return 0;
            }
            if !raw.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                return 0;
            }
            let mut name: Vec<u16> = raw.iter().map(|&b| b as u16).collect();
            name.push(0);

            // FILE_MAP_ALL_ACCESS rather than READ|WRITE, exactly like
            // PuTTY's pageant: the owner check needs READ_CONTROL, which
            // READ|WRITE does not request.
            let map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, 0, name.as_ptr());
            if map.is_null() {
                return 0;
            }
            let ok = serve_mapping(&ctx, map);
            CloseHandle(map);
            if ok {
                1
            } else {
                0
            }
        }

        /// Process the request sitting in `map` and write the framed
        /// response back at offset 0.
        unsafe fn serve_mapping(ctx: &Ctx, map: HANDLE) -> bool {
            if !mapping_belongs_to_current_user(map) {
                return false;
            }
            let view = MapViewOfFile(map, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
            if view.Value.is_null() {
                return false;
            }

            // VirtualQuery reports the mapped region (the section size
            // rounded up to page granularity); never read or write past it.
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let written = VirtualQuery(
                view.Value,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            let bound = if written != 0 { mbi.RegionSize } else { 0 };
            if bound < 5 {
                UnmapViewOfFile(view);
                return false;
            }

            let bytes = std::slice::from_raw_parts_mut(view.Value as *mut u8, bound);
            let msglen = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            let msg = if msglen == 0 || msglen > MAX_MESSAGE || 4 + msglen > bound {
                None
            } else {
                Some(&bytes[4..4 + msglen])
            };

            // A request that cannot be read (junk length, too big for the
            // mapping) gets a failure response rather than silence: the
            // client is parked on SendMessage and must see *something*.
            let response = match msg {
                Some(msg) => ctx.rt.block_on(process_message(
                    msg,
                    &ctx.keys,
                    &ctx.guard,
                    None,
                    // Pageant has no connection to bind; PuTTY doesn't
                    // send session-bind anyway.
                    &mut ConnState::default(),
                )),
                None => vec![SSH_AGENT_FAILURE],
            };
            if 4 + response.len() > bound {
                UnmapViewOfFile(view);
                return false;
            }
            bytes[..4].copy_from_slice(&u32::to_be_bytes(response.len() as u32));
            bytes[4..4 + response.len()].copy_from_slice(&response);
            UnmapViewOfFile(view);
            true
        }

        /// Copy of this process's user SID (raw bytes as returned by the
        /// OS), computed once and reused for every request.
        fn current_user_sid() -> Option<Vec<u8>> {
            use windows_sys::Win32::Security::{
                GetTokenInformation, TokenUser, SID_AND_ATTRIBUTES,
            };

            // Successful lookups only: caching a failure would disable
            // the Pageant endpoint for the rest of the run after one
            // transient error.
            static CACHE: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
            if let Some(sid) = CACHE.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                return Some(sid);
            }
            let computed = unsafe {
                let mut token = std::ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return None;
                }
                let result = (|| {
                    // First call sizes the buffer (fails with
                    // ERROR_INSUFFICIENT_BUFFER by design).
                    let mut needed = 0u32;
                    let rc =
                        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
                    if rc == 0 {
                        let err = GetLastError();
                        if err != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
                            return None;
                        }
                    }
                    let mut buf = vec![0u8; needed as usize];
                    if GetTokenInformation(
                        token,
                        TokenUser,
                        buf.as_mut_ptr() as *mut c_void,
                        needed,
                        &mut needed,
                    ) == 0
                    {
                        return None;
                    }
                    // TOKEN_USER begins with a SID_AND_ATTRIBUTES whose
                    // Sid points *into* the buffer; copy the SID out so
                    // the pointer cannot dangle.
                    let attrs = buf.as_ptr() as *const SID_AND_ATTRIBUTES;
                    copy_sid((*attrs).Sid)
                })();
                CloseHandle(token);
                result
            }?;
            *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some(computed.clone());
            Some(computed)
        }

        /// Copy a SID out of OS-owned memory into a plain byte buffer.
        unsafe fn copy_sid(sid: PSID) -> Option<Vec<u8>> {
            use windows_sys::Win32::Security::{CopySid, GetLengthSid};

            if sid.is_null() {
                return None;
            }
            let len = GetLengthSid(sid);
            if len == 0 {
                return None;
            }
            let mut copy = vec![0u8; len as usize];
            (CopySid(len, copy.as_mut_ptr() as *mut c_void, sid) != 0).then_some(copy)
        }

        /// Owner SID of `handle`, copied out of OS-owned memory.
        ///
        /// `ppSecurityDescriptor` is not optional, however tempting it is
        /// to pass NULL when the owner is all we want: `GetSecurityInfo`
        /// allocates a self-relative descriptor on every successful call
        /// and the SID it returns points *into* that allocation — which is
        /// exactly why the SID has to be copied out at all. Passing NULL
        /// does not skip the allocation, it only throws away the one
        /// pointer that could free it, once per Pageant request. MSDN
        /// documents the argument as required whenever any of the
        /// `ppsid*` / `ppDacl` / `ppSacl` outputs is non-NULL.
        unsafe fn owner_sid_of(handle: HANDLE) -> Option<Vec<u8>> {
            use windows_sys::Win32::Foundation::LocalFree;
            use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
            use windows_sys::Win32::Security::{
                OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
            };

            let mut owner: PSID = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let rc = GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            if rc != 0 {
                return None;
            }
            // Copy first, free second: `owner` dangles the moment the
            // descriptor is released.
            let copied = copy_sid(owner);
            if !sd.is_null() {
                LocalFree(sd);
            }
            copied
        }

        /// The SID this process's token uses as the *default owner* for
        /// objects created without an explicit security descriptor: the
        /// Administrators group for an elevated token, the user otherwise.
        ///
        /// PuTTY's pageant accepts either this or the user SID as a valid
        /// request-mapping owner (its `get_default_sid` / `get_user_sid`
        /// pair) — clients that pass no descriptor at all, and clients on
        /// an elevated token, produce exactly this owner.
        fn current_default_owner_sid() -> Option<Vec<u8>> {
            use windows_sys::Win32::System::Threading::{
                GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            };

            /// `READ_CONTROL` — what GetSecurityInfo needs on the handle.
            /// (Only exported by windows-sys as a file-access constant;
            /// the access mask itself is generic.)
            const READ_CONTROL: u32 = 0x0002_0000;

            // Successful lookups only, as in `current_user_sid`.
            static CACHE: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
            if let Some(sid) = CACHE.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                return Some(sid);
            }
            let computed = unsafe {
                // PuTTY asks for MAXIMUM_ALLOWED, which includes
                // READ_CONTROL.
                let proc = OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | READ_CONTROL,
                    0,
                    GetCurrentProcessId(),
                );
                if proc.is_null() {
                    return None;
                }
                let result = owner_sid_of(proc);
                CloseHandle(proc);
                result
            }?;
            *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some(computed.clone());
            Some(computed)
        }

        /// True when the request mapping's owner is this user (or this
        /// token's default owner) — PuTTY's pageant check against a
        /// different user borrowing the agent's keys.
        fn mapping_belongs_to_current_user(map: HANDLE) -> bool {
            use windows_sys::Win32::Security::{EqualSid, PSID};

            // Two acceptable owners, exactly like PuTTY's pageant: the
            // user's own SID (clients that set an explicit security
            // descriptor — winpgntc does) or the token's default owner
            // (clients that pass no descriptor at all).
            let (Some(ours), Some(default_owner)) =
                (current_user_sid(), current_default_owner_sid())
            else {
                return false; // fail closed
            };
            let Some(owned) = (unsafe { owner_sid_of(map) }) else {
                return false;
            };
            unsafe {
                EqualSid(ours.as_ptr() as PSID, owned.as_ptr() as PSID) != 0
                    || EqualSid(default_owner.as_ptr() as PSID, owned.as_ptr() as PSID) != 0
            }
        }
    } // mod pageant

    pub struct SshAgentHandle {
        pub socket_path: PathBuf,
        /// Public-only summary of every key currently exposed by the agent.
        pub keys: Vec<KeyInfo>,
        shared: AgentShared,
    }

    struct AgentShared {
        /// The agent's own multi-thread runtime. The pipe's accept loop and
        /// connection tasks live here; the Pageant window thread also parks
        /// `block_on` calls on it while a signature approval is pending.
        /// Deliberately not the Tauri runtime — the Pageant thread must be
        /// able to synchronously wait on confirmations without depending on
        /// how the host app's runtime is threaded.
        rt: Runtime,
        /// `None` only after a stop has taken it; see `SshAgentHandle::stop`.
        accept_loop: Option<JoinHandle<()>>,
        pageant: Option<pageant::PageantThread>,
        /// Denies parked confirmations on stop - a Pageant request can be
        /// sitting in the window thread's `block_on`, and joining it must
        /// not wait out the confirmation timeout.
        guard: SignGuard,
    }

    impl SshAgentHandle {
        pub async fn stop(mut self) {
            // Abort *and wait*: the aborted task owns the listening pipe
            // instance, and the next `start_agent` — which is what a
            // confirmation-policy change does — asks the OS for a *first*
            // instance, a request that fails for as long as ours is open.
            // Only the async path can wait; `start_agent` retries for the
            // benefit of the sync one.
            if let Some(loop_task) = self.shared.accept_loop.take() {
                loop_task.abort();
                let _ = loop_task.await;
            }
            self.shutdown();
        }

        /// Non-async best-effort stop, suitable for `lock` / `logout`
        /// commands that don't want to be async just for this cleanup.
        pub fn stop_sync(self) {
            self.shutdown();
        }

        fn shutdown(mut self) {
            self.shared.guard.cancel();
            if let Some(loop_task) = self.shared.accept_loop.take() {
                loop_task.abort();
            }
            // Quit the Pageant window thread, then wait for it: it can be
            // parked on a signature confirmation (bounded by the 30 s
            // confirm timeout), and the runtime must outlive any `block_on`
            // still driving it. `guard.cancel()` above is what keeps that
            // join short; `commands::ssh::stop_agent_sync` separately
            // closes the dialog the confirmation belongs to.
            if let Some(pg) = self.shared.pageant.as_ref() {
                pg.request_quit();
            }
            if let Some(pg) = self.shared.pageant.take() {
                pg.join();
            }
            // Shut the runtime down without waiting (`shutdown_background`
            // consumes it): a blocking runtime drop is not allowed from an
            // async context, and `stop()`/`stop_sync()` are both reachable
            // from inside a runtime. The background shutdown cancels any
            // still-serving connection task; the remaining fields drop
            // with `self`.
            self.shared.rt.shutdown_background();
        }
    }

    /// OpenSSH on Windows expects exactly this pipe name; no env var is
    /// involved, clients probe it automatically.
    pub fn default_socket_path() -> Result<PathBuf> {
        Ok(PathBuf::from(r"\\.\pipe\openssh-ssh-agent"))
    }

    /// Accept either a full `\\.\pipe\name` path or a bare name and return
    /// the canonical pipe name.
    fn full_pipe_name(path: &std::path::Path) -> String {
        let s = path.to_string_lossy();
        if s.starts_with(r"\\.\pipe\") || s.starts_with(r"\\?\pipe\") || s.starts_with("//./pipe/")
        {
            s.into_owned()
        } else {
            format!(r"\\.\pipe\{s}")
        }
    }

    /// Best-effort identity of the process connected to `server`.
    ///
    /// `GetNamedPipeClientProcessId` works on the server handle while the
    /// client is connected, so it is resolved right after `connect()`.
    fn peer_caller(
        server: &tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> Option<CallerInfo> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

        let mut pid = 0u32;
        let ok = unsafe { GetNamedPipeClientProcessId(server.as_raw_handle() as _, &mut pid) };
        if ok == 0 || pid == 0 {
            return None;
        }
        Some(CallerInfo {
            pid,
            name: process_name(pid),
        })
    }

    /// Resolve a pid to a process name via the image file name. Returns the
    /// bare executable name (e.g. `ssh.exe`), cleaned the same way as the
    /// Unix `/proc/<pid>/comm` label.
    fn process_name(pid: u32) -> Option<String> {
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        // A process may exit (or be a protected process) between the pid
        // read and this open — any failure just means "unknown caller".
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return None;
        }
        let mut name = String::with_capacity(260);
        // Grow the buffer if the path is longer than the initial guess.
        let mut len = 260u32;
        let mut ok = false;
        loop {
            let mut wide = vec![0u16; len as usize];
            let mut needed = len;
            let rc =
                unsafe { QueryFullProcessImageNameW(process, 0, wide.as_mut_ptr(), &mut needed) };
            if rc != 0 {
                wide.truncate(needed as usize);
                name = String::from_utf16_lossy(&wide);
                ok = true;
                break;
            }
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err == windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER && len < 64 * 1024 {
                len = (len.saturating_mul(2)).min(64 * 1024);
                continue;
            }
            break;
        }
        unsafe { windows_sys::Win32::Foundation::CloseHandle(process) };

        if !ok {
            return None;
        }
        // The image path is attacker-influenced text heading for a dialog:
        // keep just the file name, printable, short, single-line.
        let file = name.rsplit(['\\', '/']).next().unwrap_or(&name);
        super::proto::sanitize_process_label(file)
    }

    pub async fn start_agent(
        path: PathBuf,
        keys: Vec<AgentKey>,
        guard: SignGuard,
    ) -> Result<SshAgentHandle> {
        let rt = Runtime::new().map_err(|e| Error::Storage {
            reason: format!("cannot create agent runtime: {e}"),
        })?;
        let pipe_name = full_pipe_name(&path);

        let store: KeyStore = Arc::new(tokio::sync::Mutex::new(keys));
        let key_summaries: Vec<KeyInfo> = {
            let store = store.lock().await;
            store.iter().map(KeyInfo::from).collect()
        };

        // First pipe instance, declared as such so that any *other* agent
        // holding `\\.\pipe\openssh-ssh-agent` (the Windows OpenSSH
        // ssh-agent service, another Pageant-compatible app, a second
        // Clavix) makes this call fail instead of silently coexisting and
        // splitting clients between two agents.
        //
        // Named-pipe handles bind to the reactor that created them, and
        // everything below runs on the agent's own runtime — so the first
        // instance is created there too, with the outcome reported back
        // through a oneshot. Creating it on the caller's runtime (e.g.
        // Tauri's) and connecting it on ours would cross reactor
        // registrations and fail at the first accept.
        let first = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let name = pipe_name.clone();
            rt.spawn(async move {
                let mut attempt = 0u32;
                let result = loop {
                    let result = ServerOptions::new()
                        .first_pipe_instance(true)
                        .access_inbound(true)
                        .access_outbound(true)
                        .create(&name);
                    // tokio maps ERROR_ACCESS_DENIED — both a competing
                    // agent and our own previous instance still closing —
                    // to PermissionDenied. Only the second one clears up
                    // on its own, so retry before believing it.
                    let retryable = matches!(&result, Err(e)
                        if e.kind() == std::io::ErrorKind::PermissionDenied)
                        && attempt < FIRST_INSTANCE_RETRIES;
                    if !retryable {
                        break result;
                    }
                    attempt += 1;
                    tokio::time::sleep(FIRST_INSTANCE_RETRY_DELAY).await;
                };
                let _ = tx.send(result);
            });
            match rx.await {
                Ok(Ok(server)) => server,
                Ok(Err(e)) => {
                    // tokio maps ERROR_ACCESS_DENIED from a competing
                    // first instance to PermissionDenied.
                    let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        " — is the Windows OpenSSH ssh-agent service running \
                         (`Get-Service ssh-agent`), or another Pageant-compatible \
                         program running? Stop it and retry"
                    } else {
                        ""
                    };
                    // This whole function runs inside a runtime; a bare
                    // drop of our runtime here would panic.
                    rt.shutdown_background();
                    return Err(Error::Storage {
                        reason: format!("bind {pipe_name}: {e}{hint}"),
                    });
                }
                Err(_) => {
                    rt.shutdown_background();
                    return Err(Error::Storage {
                        reason: "agent runtime stopped while creating the pipe".into(),
                    });
                }
            }
        };

        let accept_loop = {
            let store_loop = store.clone();
            let guard_loop = guard.clone();
            let rt_handle = rt.handle().clone();
            let pipe_name_loop = pipe_name.clone();
            rt.spawn(async move {
                // One instance listening at a time; accepted connections
                // are served concurrently by their own tasks. Windows
                // OpenSSH clients connect once per request and don't
                // expect a pool.
                let mut listening = first;
                let mut consecutive_errors = 0u32;
                loop {
                    let accepted = listening.connect().await;

                    // Replenish before the accepted connection is handed
                    // off, and whatever the accept returned. A client that
                    // opens the pipe while no instance is listening is
                    // told it is busy rather than queued, so the ordering
                    // keeps that window as short as it can be — and, more
                    // to the point, keeps it independent of whatever else
                    // ends up between the accept and the hand-off later.
                    // No first-instance flag here: ours is already in.
                    let next = match ServerOptions::new()
                        .access_inbound(true)
                        .access_outbound(true)
                        .create(&pipe_name_loop)
                    {
                        Ok(next) => next,
                        Err(e) => {
                            eprintln!(
                                "[clavix agent] cannot recreate a listening instance on \
                                 {pipe_name_loop}, the endpoint stops here: {e}"
                            );
                            return;
                        }
                    };
                    let server = std::mem::replace(&mut listening, next);

                    if let Err(e) = accepted {
                        eprintln!("[clavix agent] pipe connect failed on {pipe_name_loop}: {e}");
                        consecutive_errors += 1;
                        if consecutive_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                            eprintln!(
                                "[clavix agent] {consecutive_errors} accepts in a row failed on \
                                 {pipe_name_loop}, the endpoint stops here"
                            );
                            return;
                        }
                        continue;
                    }
                    consecutive_errors = 0;

                    let store = store_loop.clone();
                    let guard = guard_loop.clone();
                    rt_handle.spawn(async move {
                        // Resolve the caller right after accept: the pid is
                        // only meaningful while the client is connected.
                        let caller = peer_caller(&server);
                        if let Err(e) = serve(server, store, guard, caller).await {
                            eprintln!("[clavix agent] connection error: {e}");
                        }
                    });
                }
            })
        };

        // The PuTTY endpoint is best-effort: when a real Pageant (or any
        // other Pageant-compatible agent) is already running, clients will
        // find it anyway — serving alongside would split plink traffic
        // between two agents, so we simply don't start.
        let pageant_thread =
            pageant::spawn_if_free(store.clone(), guard.clone(), rt.handle().clone());

        Ok(SshAgentHandle {
            socket_path: path,
            keys: key_summaries,
            shared: AgentShared {
                rt,
                accept_loop: Some(accept_loop),
                pageant: pageant_thread,
                guard,
            },
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use super::super::proto::SignPolicy;

        /// Pageant window class + title are process-global: two agents (or
        /// two tests) would make `FindWindow` pick an arbitrary one. Every
        /// test that starts an agent serializes on this lock.
        static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

        /// Find OUR agent's Pageant window, ignoring any incumbent owned
        /// by another process (ssh-pageant, PuTTY's Pageant, …).
        /// `FindWindowW` would return an arbitrary match; this walks the
        /// top-level windows with `FindWindowExW` and filters by owning
        /// process id.
        unsafe fn find_own_pageant_window() -> *mut std::ffi::c_void {
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                EnumWindows, GetClassNameW, GetWindowTextW, GetWindowThreadProcessId,
            };

            thread_local! {
                /// Set by `visit` when our window is found.
                static MATCH: std::cell::Cell<isize> = const { std::cell::Cell::new(0) };
            }

            unsafe extern "system" fn visit(hwnd: *mut std::ffi::c_void, _: isize) -> i32 {
                // "Pageant", as UTF-16 code units.
                const NAME: [u16; 7] = [80, 97, 103, 101, 97, 110, 116];

                unsafe {
                    let mut class = [0u16; 32];
                    let n = GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32);
                    if n as usize != NAME.len() || class[..NAME.len()] != NAME {
                        return 1;
                    }
                    let mut title = [0u16; 32];
                    let m = GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32);
                    if m as usize != NAME.len() || title[..NAME.len()] != NAME {
                        return 1;
                    }
                    let mut pid = 0u32;
                    GetWindowThreadProcessId(hwnd, &mut pid);
                    if pid == std::process::id() {
                        MATCH.with(|cell| cell.set(hwnd as isize));
                        return 0; // stop enumerating
                    }
                    1
                }
            }

            MATCH.with(|cell| cell.set(0));
            EnumWindows(Some(visit), 0);
            MATCH.with(|cell| cell.get()) as *mut std::ffi::c_void
        }

        /// A fresh unencrypted Ed25519 key, loaded through the same path
        /// the real start command uses.
        fn make_key(comment: &str) -> AgentKey {
            use ssh_key::{Algorithm, LineEnding, PrivateKey};

            let mut rng = rand::thread_rng();
            let pk = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
            let pem = pk.to_openssh(LineEnding::LF).unwrap().to_string();
            super::super::proto::try_load_agent_key(&pem, comment)
                .unwrap()
                .expect("ed25519 keys always load")
        }

        fn unique_pipe(suffix: &str) -> String {
            format!(
                r"\\.\pipe\clavix-agent-test-{}-{suffix}",
                std::process::id()
            )
        }

        fn frame(message: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(4 + message.len());
            out.extend_from_slice(&u32::to_be_bytes(message.len() as u32));
            out.extend_from_slice(message);
            out
        }

        /// Read one framed response ([u32 BE length][payload]) off a
        /// client connection.
        async fn read_frame<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
            use tokio::io::AsyncReadExt;

            let mut hdr = [0u8; 4];
            stream.read_exact(&mut hdr).await.unwrap();
            let len = u32::from_be_bytes(hdr) as usize;
            let mut resp = vec![0u8; len];
            stream.read_exact(&mut resp).await.unwrap();
            resp
        }

        #[test]
        fn named_pipe_serves_list_and_sign() {
            let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            use tokio::io::AsyncWriteExt as _;

            let key = make_key("pipe-test");
            let blob = key.pub_blob.clone();
            let name = unique_pipe("pipe");
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                let handle = start_agent(
                    PathBuf::from(&name),
                    vec![key],
                    SignGuard::new(SignPolicy::Never, None),
                )
                .await
                .unwrap();

                let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
                    .open(&name)
                    .unwrap();

                // REQUEST_IDENTITIES -> exactly our one key.
                client.write_all(&frame(&[11])).await.unwrap();
                let resp = read_frame(&mut client).await;
                assert_eq!(resp[0], 12); // SSH_AGENT_IDENTITIES_ANSWER
                assert_eq!(u32::from_be_bytes(resp[1..5].try_into().unwrap()), 1);
                let mut r = super::super::proto::SshReader::new(&resp[5..]);
                assert_eq!(r.read_string().unwrap(), blob.as_slice());

                // SIGN_REQUEST on the same connection -> ssh-ed25519 sig.
                let mut req = vec![13]; // SSH_AGENTC_SIGN_REQUEST
                super::super::proto::write_string(&mut req, &blob);
                super::super::proto::write_string(&mut req, b"data-to-sign");
                req.extend_from_slice(&u32::to_be_bytes(0));
                client.write_all(&frame(&req)).await.unwrap();
                let resp = read_frame(&mut client).await;
                assert_eq!(resp[0], 14); // SSH_AGENT_SIGN_RESPONSE
                let mut r = super::super::proto::SshReader::new(&resp[1..]);
                let sig_blob = r.read_string().unwrap();
                let mut inner = super::super::proto::SshReader::new(sig_blob);
                assert_eq!(inner.read_string().unwrap(), b"ssh-ed25519");
                assert_eq!(inner.read_string().unwrap().len(), 64);

                handle.stop().await;
            });
        }

        /// A stop must never wait on a parked confirmation: a Pageant
        /// request under the "always ask" policy whose prompt never answers
        /// has the window thread parked in `block_on`, and `stop()` itself
        /// must deny it — not leave the caller waiting on a timeout.
        #[test]
        fn stopping_denies_a_parked_pageant_confirmation() {
            let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
            use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
            use windows_sys::Win32::System::Memory::{
                CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE, PAGE_READWRITE,
            };
            use windows_sys::Win32::System::Threading::GetCurrentThreadId;
            use windows_sys::Win32::UI::WindowsAndMessaging::{SendMessageW, WM_COPYDATA};

            let key = make_key("cancel-test");
            let blob = key.pub_blob.clone();
            let name = unique_pipe("cancel");

            // The prompt never answers; cancellation is what ends the wait.
            // The channel tells the test the request is parked inside the
            // agent before it calls stop.
            let (parked_tx, parked_rx) = std::sync::mpsc::channel::<()>();
            let confirm: super::super::proto::ConfirmFn = Arc::new(move |_req| {
                let _ = parked_tx.send(());
                Box::pin(std::future::pending::<bool>())
            });
            let guard = SignGuard::new(SignPolicy::Always, Some(confirm));

            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                super::TEST_FORCE_PAGEANT.store(true, std::sync::atomic::Ordering::Relaxed);
                let handle = start_agent(PathBuf::from(&name), vec![key], guard)
                    .await
                    .unwrap();
                super::TEST_FORCE_PAGEANT.store(false, std::sync::atomic::Ordering::Relaxed);

                let hwnd = unsafe { find_own_pageant_window() };
                assert!(
                    !hwnd.is_null(),
                    "start_agent should create a Pageant window"
                );

                // The client blocks in SendMessage until the agent answers.
                let hwnd_addr = hwnd as isize;
                let blob_for_thread = blob.clone();
                let client = std::thread::spawn(move || unsafe {
                    let map_name = format!("PageantRequest{:08x}", GetCurrentThreadId());
                    let mut name_wide: Vec<u16> = map_name.encode_utf16().collect();
                    name_wide.push(0);
                    let mut name_bytes = map_name.into_bytes();
                    name_bytes.push(0);

                    let hmap = CreateFileMappingW(
                        INVALID_HANDLE_VALUE,
                        std::ptr::null(),
                        PAGE_READWRITE,
                        0,
                        256 * 1024,
                        name_wide.as_ptr(),
                    );
                    assert!(!hmap.is_null(), "client mapping");
                    let view = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, 0);
                    assert!(!view.Value.is_null(), "client view");
                    let bytes = std::slice::from_raw_parts_mut(view.Value as *mut u8, 256 * 1024);

                    let mut req = vec![13u8]; // SSH_AGENTC_SIGN_REQUEST
                    super::super::proto::write_string(&mut req, &blob_for_thread);
                    super::super::proto::write_string(&mut req, b"cancel-test-data");
                    req.extend_from_slice(&u32::to_be_bytes(0));
                    let framed = frame(&req);
                    bytes[..framed.len()].copy_from_slice(&framed);

                    let cds = COPYDATASTRUCT {
                        dwData: 0x804e50ba, // AGENT_COPYDATA_ID
                        cbData: name_bytes.len() as u32,
                        lpData: name_bytes.as_mut_ptr() as *mut std::ffi::c_void,
                    };
                    let result = SendMessageW(
                        hwnd_addr as *mut std::ffi::c_void,
                        WM_COPYDATA,
                        0,
                        (&cds as *const COPYDATASTRUCT) as isize,
                    );
                    let first = if result > 0 {
                        let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
                        Some(bytes[4..4 + len][0])
                    } else {
                        None
                    };
                    UnmapViewOfFile(view);
                    CloseHandle(hmap);
                    first
                });

                parked_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .expect("the agent should park on the confirmation");
                let started = std::time::Instant::now();
                handle.stop().await;
                let elapsed = started.elapsed();
                assert!(
                    elapsed < std::time::Duration::from_secs(2),
                    "stop must cancel a parked confirmation, took {elapsed:?}"
                );
                assert_eq!(
                    client.join().expect("client thread"),
                    Some(5), // SSH_AGENT_FAILURE: the parked request was denied
                );
            });
        }

        #[test]
        fn peer_caller_reports_the_connecting_process() {
            let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            use tokio::net::windows::named_pipe::ClientOptions;

            let name = unique_pipe("peer");
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let server = ServerOptions::new().create(&name).unwrap();
                let connect =
                    tokio::spawn(async move { ClientOptions::new().open(&name).unwrap() });
                server.connect().await.unwrap();
                let client = connect.await.unwrap();

                let caller = peer_caller(&server).expect("caller resolvable");
                assert_eq!(caller.pid, std::process::id());
                let caller_name = caller.name.expect("image name readable for a live process");
                assert!(!caller_name.is_empty());
                assert!(
                    !caller_name.contains('\n'),
                    "name must be a single line: {caller_name:?}"
                );
                drop(client);
            });
        }

        #[test]
        fn process_name_is_none_for_an_unknown_pid() {
            assert_eq!(process_name(u32::MAX), None);
        }

        #[test]
        fn a_competing_first_instance_yields_a_clear_error() {
            let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            let name = unique_pipe("conflict");
            let rt = tokio::runtime::Runtime::new().unwrap();
            let blocker = rt.block_on(async {
                ServerOptions::new()
                    .first_pipe_instance(true)
                    .create(&name)
                    .unwrap()
            });

            let err = match rt.block_on(start_agent(
                PathBuf::from(&name),
                Vec::new(),
                SignGuard::new(SignPolicy::Never, None),
            )) {
                Err(e) => e,
                Ok(h) => {
                    rt.block_on(h.stop());
                    panic!("a competing first instance must be refused");
                }
            };
            match err {
                Error::Storage { reason } => {
                    assert!(
                        reason.contains("ssh-agent"),
                        "error should point at the likely owner: {reason}"
                    );
                }
                other => panic!("expected Storage error, got {other:?}"),
            }
            drop(blocker);
        }

        /// A stop hands the agent's runtime to `shutdown_background()`, so
        /// the instance it was listening on can still be open when the
        /// next start asks the OS for a *first* instance. Changing the
        /// confirmation policy does exactly this — stop, then start again
        /// on the same name — and the OS's ACCESS_DENIED used to surface
        /// as "is the Windows OpenSSH ssh-agent service running?", with no
        /// agent left behind to contradict it.
        #[test]
        fn restarting_immediately_after_a_stop_succeeds() {
            let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            use tokio::io::AsyncWriteExt as _;

            let name = unique_pipe("restart");
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                let mut handle = start_agent(
                    PathBuf::from(&name),
                    vec![make_key("restart")],
                    SignGuard::new(SignPolicy::Never, None),
                )
                .await
                .unwrap();

                // Three in a row: one restart could get lucky on timing.
                for _ in 0..3 {
                    handle.stop().await;
                    handle = start_agent(
                        PathBuf::from(&name),
                        vec![make_key("restart")],
                        SignGuard::new(SignPolicy::Never, None),
                    )
                    .await
                    .expect("a restart must not be taken for a competing agent");
                }

                // ...and the endpoint the last start returned actually
                // serves, rather than merely having been created.
                let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
                    .open(&name)
                    .unwrap();
                client.write_all(&frame(&[11])).await.unwrap();
                let resp = read_frame(&mut client).await;
                assert_eq!(resp[0], 12); // SSH_AGENT_IDENTITIES_ANSWER

                handle.stop().await;
            });
        }

        /// Full PuTTY-client emulation against our own Pageant window:
        /// FindWindow, shared `PageantRequest%08x` mapping, WM_COPYDATA,
        /// response read back from the mapping.
        #[test]
        fn pageant_ipc_serves_list_and_sign() {
            let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            use windows_sys::core::w;
            use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
            use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
            use windows_sys::Win32::System::Memory::{
                CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE, PAGE_READWRITE,
            };
            use windows_sys::Win32::System::Threading::GetCurrentThreadId;
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                CreateWindowExW, DestroyWindow, SendMessageW, WM_COPYDATA,
            };

            let key = make_key("pageant-test");
            let blob = key.pub_blob.clone();
            let name = unique_pipe("pageant");
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                // Force our own window even when an incumbent agent (e.g.
                // ssh-pageant) owns the "Pageant" name on this machine —
                // production yields to the incumbent, the test wants ours.
                super::TEST_FORCE_PAGEANT.store(true, std::sync::atomic::Ordering::Relaxed);
                let handle = start_agent(
                    PathBuf::from(&name),
                    vec![key],
                    SignGuard::new(SignPolicy::Never, None),
                )
                .await
                .unwrap();
                super::TEST_FORCE_PAGEANT.store(false, std::sync::atomic::Ordering::Relaxed);

                unsafe {
                    let mut hwnd = find_own_pageant_window();
                    if hwnd.is_null() {
                        // Rules out a visibility/publication race before the
                        // environment probe below — cheap, and turns a
                        // would-be flake into a pass with a note.
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        hwnd = find_own_pageant_window();
                        if !hwnd.is_null() {
                            eprintln!("[test] Pageant window appeared after a short retry");
                        }
                    }
                    if hwnd.is_null() {
                        // The endpoint is best-effort, so a missing window
                        // can mean either "this environment cannot create
                        // windows at all" (locked-down CI sessions) or a
                        // real regression. Probe with a system class to
                        // tell them apart, and in the second case carry
                        // the recorded reason into the failure.
                        let probe = CreateWindowExW(
                            0,
                            w!("STATIC"),
                            w!("clavix-probe"),
                            0,
                            0,
                            0,
                            0,
                            0,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            std::ptr::null(),
                        );
                        let can_create_windows = !probe.is_null();
                        if can_create_windows {
                            DestroyWindow(probe);
                        }
                        let reason = super::pageant::last_unavailable_reason()
                            .unwrap_or_else(|| "no reason recorded".into());
                        if !can_create_windows {
                            eprintln!(
                                "[test] this environment cannot create windows - skipping \
                                 Pageant protocol checks (endpoint: {reason})"
                            );
                            handle.stop().await;
                            return;
                        }
                        let forensics = super::pageant::last_window_forensics();
                        panic!(
                            "start_agent should create a Pageant window, but none is \
                             findable: {reason}; {forensics}"
                        );
                    }
                    let map_name = format!("PageantRequest{:08x}", GetCurrentThreadId());
                    let mut name_wide: Vec<u16> = map_name.encode_utf16().collect();
                    name_wide.push(0);
                    let mut name_bytes = map_name.into_bytes();
                    name_bytes.push(0);

                    // One mapping per request, exactly like winpgntc. The
                    // agent must accept both owner shapes a client can
                    // produce: no security descriptor (owner = the token's
                    // default owner) and an explicit one owned by the user
                    // SID (what winpgntc itself passes when advapi is
                    // available). Exercise each in turn below.
                    let user_sid = super::pageant::user_sid_for_test().expect("token user SID");
                    let mut run_request = |msg: &[u8], with_sd: bool| -> Vec<u8> {
                        let mut sd: windows_sys::Win32::Security::SECURITY_DESCRIPTOR =
                            std::mem::zeroed();
                        let mut sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES =
                            std::mem::zeroed();
                        let attrs: *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES =
                            if with_sd {
                                windows_sys::Win32::Security::InitializeSecurityDescriptor(
                                    &mut sd as *mut _ as *mut std::ffi::c_void,
                                    1, // SECURITY_DESCRIPTOR_REVISION
                                );
                                windows_sys::Win32::Security::SetSecurityDescriptorOwner(
                                    &mut sd as *mut _ as *mut std::ffi::c_void,
                                    user_sid.as_ptr() as windows_sys::Win32::Security::PSID,
                                    0,
                                );
                                sa.nLength = std::mem::size_of_val(&sa) as u32;
                                sa.lpSecurityDescriptor =
                                    &mut sd as *mut _ as *mut std::ffi::c_void;
                                &sa
                            } else {
                                std::ptr::null()
                            };
                        let hmap = CreateFileMappingW(
                            INVALID_HANDLE_VALUE,
                            attrs,
                            PAGE_READWRITE,
                            0,
                            256 * 1024,
                            name_wide.as_ptr(),
                        );
                        assert!(!hmap.is_null(), "client mapping creation");
                        let view = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, 0);
                        assert!(!view.Value.is_null(), "client view mapping");
                        let bytes =
                            std::slice::from_raw_parts_mut(view.Value as *mut u8, 256 * 1024);
                        let framed = frame(msg);
                        bytes[..framed.len()].copy_from_slice(&framed);

                        let cds = COPYDATASTRUCT {
                            dwData: 0x804e50ba, // AGENT_COPYDATA_ID
                            cbData: name_bytes.len() as u32,
                            lpData: name_bytes.as_mut_ptr() as *mut std::ffi::c_void,
                        };
                        let result = SendMessageW(
                            hwnd,
                            WM_COPYDATA,
                            0,
                            (&cds as *const COPYDATASTRUCT) as isize,
                        );
                        assert!(result > 0, "the agent should answer this request");
                        // Response is written at the mapping start,
                        // length-prefixed like the socket protocol.
                        let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
                        let resp = bytes[4..4 + len].to_vec();
                        UnmapViewOfFile(view);
                        CloseHandle(hmap);
                        resp
                    };

                    let resp = run_request(&[11], false); // no SD: default-owner path
                    assert_eq!(resp[0], 12);
                    let mut r = super::super::proto::SshReader::new(&resp[5..]);
                    assert_eq!(r.read_string().unwrap(), blob.as_slice());

                    let mut req = vec![13];
                    super::super::proto::write_string(&mut req, &blob);
                    super::super::proto::write_string(&mut req, b"data-for-pageant");
                    req.extend_from_slice(&u32::to_be_bytes(0));
                    let resp = run_request(&req, true); // explicit user-SID SD: winpgntc's shape
                    assert_eq!(resp[0], 14);
                    let mut r = super::super::proto::SshReader::new(&resp[1..]);
                    let sig_blob = r.read_string().unwrap();
                    let mut inner = super::super::proto::SshReader::new(sig_blob);
                    assert_eq!(inner.read_string().unwrap(), b"ssh-ed25519");
                    assert_eq!(inner.read_string().unwrap().len(), 64);

                    handle.stop().await;
                }
            });
        }
    }
} // mod windows

#[cfg(not(any(unix, windows)))]
mod stub {
    use std::path::PathBuf;

    use super::proto::{AgentKey, KeyInfo, SignGuard};
    use clavix_core::error::{Error, Result};

    pub struct SshAgentHandle {
        pub socket_path: PathBuf,
        pub keys: Vec<KeyInfo>,
    }

    impl SshAgentHandle {
        pub async fn stop(self) {}
        pub fn stop_sync(self) {}
    }

    pub fn default_socket_path() -> Result<PathBuf> {
        Err(Error::Storage {
            reason: "SSH agent is only supported on Unix and Windows for now".into(),
        })
    }

    pub async fn start_agent(
        _path: PathBuf,
        _keys: Vec<AgentKey>,
        _guard: SignGuard,
    ) -> Result<SshAgentHandle> {
        Err(Error::Storage {
            reason: "SSH agent is only supported on Unix and Windows for now".into(),
        })
    }
}

pub use proto::{try_load_agent_key, ConfirmFn, HostHop, SignGuard, SignPolicy, SignRequest};
#[cfg_attr(not(phone_approval), allow(unused_imports))]
pub use proto::{AgentKey, PhoneSignFuture, PhoneSigner};
#[cfg(all(test, phone_approval))]
pub use proto::{CallerInfo, KeyInfo};

#[cfg(not(any(unix, windows)))]
pub use stub::{default_socket_path, start_agent, SshAgentHandle};
#[cfg(unix)]
pub use unix::{default_socket_path, start_agent, SshAgentHandle};
#[cfg(windows)]
pub use windows::{default_socket_path, start_agent, SshAgentHandle};
