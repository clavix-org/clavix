//! Approving SSH-agent signatures on a paired phone.
//!
//! The phone never signs: it returns a "yes" proven by its approval key,
//! and only then does the agent sign with the vault key, exactly as after
//! a click in the local dialog. The wire format (pairing, sealed requests,
//! proofs) lives in the clavix-approve project ("Approve mode" of its
//! PROTOCOL.md); this module only holds what Clavix decides on its own:
//! when the phone is asked, how its answer races the local dialog, and
//! what each outcome means.
//!
//! The rules (clavix-approve DESKTOP_APPROVAL.md, "When the phone is
//! asked"):
//!
//! - session unlocked: the dialog at once, the phone after `delay`
//!   (0 = both at once);
//! - screen locked: the phone only, at once; the dialog comes up if the
//!   screen is unlocked while the request waits;
//! - the first answer wins and the other prompt is withdrawn; a deny from
//!   either side denies;
//! - once the phone is involved the whole request may take 90 s instead
//!   of the dialog's 30 s;
//! - a phone that cannot be reached (relay down, not paired) changes
//!   nothing: the dialog is shown, as without the feature.
//!
//! Kept free of any Tauri type, like `ssh_agent`, so the decision logic is
//! tested on its own.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::ssh_agent::SignRequest;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// How long a request may wait once the phone is involved: under sshd's
/// default `LoginGraceTime` (120 s), as `clavix-agent` does.
pub const PHONE_TIMEOUT: Duration = Duration::from_secs(90);
/// How often a request waiting behind a locked screen checks whether the
/// screen was unlocked, to bring the dialog back.
const LOCK_POLL: Duration = Duration::from_secs(2);
/// Upper bound for the user's delay setting.
pub const MAX_DELAY: Duration = Duration::from_secs(60);

/// One session binding, as the phone re-verifies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub hostkey: Vec<u8>,
    pub sid: Vec<u8>,
    pub sig: Vec<u8>,
    pub fwd: bool,
}

/// What Clavix shows to the user, unverified by the phone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub pid: u32,
    pub name: Option<String>,
}

/// The content of an `approve` request (clavix-approve PROTOCOL.md,
/// "Approval request"), before sealing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// Local id, 32 hex digits, chosen here so the request can be
    /// withdrawn. The relay client derives the per-device ids from it.
    pub id: String,
    pub key_blob: Vec<u8>,
    pub key_name: String,
    pub data: Vec<u8>,
    pub flags: u32,
    /// Outermost first.
    pub binds: Vec<Bind>,
    pub caller: Option<Caller>,
    /// This machine's label.
    pub agent: String,
    /// Host key fingerprint → name from `known_hosts`. A hint only: the
    /// phone shows the name it pinned itself.
    pub hints: BTreeMap<String, String>,
    pub ttl_s: u32,
}

impl ApprovalRequest {
    /// Build the phone's request from what the agent asked the user.
    /// `hints` maps host key fingerprints to `known_hosts` names.
    pub fn from_sign_request(
        req: &SignRequest,
        agent: String,
        hints: BTreeMap<String, String>,
    ) -> Self {
        Self {
            id: new_request_id(),
            key_blob: req.key_blob.clone(),
            key_name: req.key.comment.clone(),
            data: req.data.clone(),
            flags: req.flags,
            binds: req
                .hops
                .iter()
                .map(|h| Bind {
                    hostkey: h.key_blob.clone(),
                    sid: h.session_id.clone(),
                    sig: h.signature.clone(),
                    fwd: h.forwarded,
                })
                .collect(),
            caller: req.caller.as_ref().map(|c| Caller {
                pid: c.pid,
                name: c.name.clone(),
            }),
            agent,
            hints,
            ttl_s: PHONE_TIMEOUT.as_secs() as u32,
        }
    }
}

fn new_request_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The phone's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhoneAnswer {
    /// Approved, and the proof verified under the approval key recorded
    /// at pairing. Nothing else may produce this variant.
    Approved,
    /// The user refused on the phone (or the phone rejected the request).
    Denied(String),
    /// The phone could not be asked or did not answer in a usable way:
    /// relay unreachable, not paired, an answer that does not verify.
    /// Never a deny on its own: the dialog stays the fallback.
    Unavailable(String),
}

/// A paired phone, behind the relay. Implemented over the shared
/// clavix-approve crate; tests use fakes.
pub trait PhoneApprover: Send + Sync {
    /// Ask the phone and wait for its answer. Must give up by itself
    /// (`Unavailable`) once `req.ttl_s` has passed.
    fn approve(&self, req: ApprovalRequest) -> BoxFuture<PhoneAnswer>;
    /// Withdraw a pending request (the dialog answered first, or the
    /// agent is stopping). Fire and forget; must not block.
    fn withdraw(&self, id: &str);
    fn is_paired(&self) -> bool;
}

/// The local confirmation dialog for one request.
pub trait ConfirmDialog: Send + Sync {
    /// Show the dialog and wait for the user, denying after `timeout`.
    /// `phone_asked` tells the dialog to say the phone was asked too.
    fn open(&self, timeout: Duration, phone_asked: bool) -> BoxFuture<bool>;
    /// Close the dialog if it is still up (the phone answered first).
    fn close(&self);
}

/// `Some(true)` locked, `Some(false)` unlocked, `None` unknown (treated
/// as unlocked).
pub type LockProbe = Arc<dyn Fn() -> BoxFuture<Option<bool>> + Send + Sync>;

/// Withdraws the phone request if the race is dropped before an answer
/// (the agent stopping cancels the future that owns it).
struct PendingPhone {
    phone: Arc<dyn PhoneApprover>,
    id: String,
    armed: bool,
}

impl Drop for PendingPhone {
    fn drop(&mut self) {
        if self.armed {
            self.phone.withdraw(&self.id);
        }
    }
}

/// Closes the dialog if the race is dropped while it is up.
struct OpenDialog<'a> {
    dialog: &'a dyn ConfirmDialog,
    armed: bool,
}

impl Drop for OpenDialog<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.dialog.close();
        }
    }
}

/// Ask the dialog and the phone for one signature, per the rules in the
/// module doc. Returns `true` only on an approval from either side, with
/// no deny before it.
pub async fn race(
    req: ApprovalRequest,
    phone: Arc<dyn PhoneApprover>,
    dialog: &dyn ConfirmDialog,
    delay: Duration,
    screen_locked: LockProbe,
) -> bool {
    use tokio::time::{sleep_until, Instant};

    let start = Instant::now();
    let deadline = start + PHONE_TIMEOUT;
    let delay = delay.min(MAX_DELAY);
    let locked = screen_locked().await == Some(true);

    let mut dialog_fut: Option<BoxFuture<bool>> = None;
    let mut dialog_guard = OpenDialog {
        dialog,
        armed: false,
    };
    let open_dialog = |at: Instant, guard: &mut OpenDialog<'_>| {
        guard.armed = true;
        dialog.open(deadline.saturating_duration_since(at), true)
    };
    if !locked {
        dialog_fut = Some(open_dialog(start, &mut dialog_guard));
    }

    let phone_at = if locked { start } else { start + delay };
    let mut phone_fut: Option<BoxFuture<PhoneAnswer>> = None;
    let mut phone_guard = PendingPhone {
        phone: phone.clone(),
        id: req.id.clone(),
        armed: false,
    };
    let mut phone_over = false;
    let mut req = Some(req);

    loop {
        tokio::select! {
            _ = sleep_until(deadline) => return false,

            approved = async { dialog_fut.as_mut().unwrap().await }, if dialog_fut.is_some() => {
                // The dialog closed itself by answering.
                dialog_guard.armed = false;
                // The phone guard withdraws a pending phone request.
                return approved;
            }

            _ = sleep_until(phone_at), if phone_fut.is_none() && !phone_over => {
                let r = req.take().expect("the phone is asked once");
                phone_guard.armed = true;
                phone_fut = Some(phone.approve(r));
            }

            answer = async { phone_fut.as_mut().unwrap().await }, if phone_fut.is_some() => {
                phone_fut = None;
                phone_over = true;
                match answer {
                    PhoneAnswer::Approved => {
                        phone_guard.armed = false;
                        return true;
                    }
                    PhoneAnswer::Denied(_) => {
                        phone_guard.armed = false;
                        return false;
                    }
                    PhoneAnswer::Unavailable(_) => {
                        // Withdrawing is harmless if the request never
                        // reached the relay; keep the guard armed.
                        if dialog_fut.is_none() {
                            dialog_fut = Some(open_dialog(Instant::now(), &mut dialog_guard));
                        }
                    }
                }
            }

            _ = tokio::time::sleep(LOCK_POLL), if dialog_fut.is_none() => {
                if screen_locked().await != Some(true) {
                    dialog_fut = Some(open_dialog(Instant::now(), &mut dialog_guard));
                }
            }
        }
    }
}

/// A phone that is never there: what runs until the relay client is
/// built in, and when nothing is paired.
pub struct NoPhone;

impl PhoneApprover for NoPhone {
    fn approve(&self, _req: ApprovalRequest) -> BoxFuture<PhoneAnswer> {
        Box::pin(async { PhoneAnswer::Unavailable("no phone paired".into()) })
    }
    fn withdraw(&self, _id: &str) {}
    fn is_paired(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::oneshot;
    use tokio::time::Instant;

    /// A phone answering `answer` after `after`, recording what it saw.
    struct FakePhone {
        answer: PhoneAnswer,
        after: Duration,
        asked_at: Mutex<Option<Instant>>,
        withdrawn: Mutex<Vec<String>>,
    }

    impl FakePhone {
        fn new(answer: PhoneAnswer, after: Duration) -> Arc<Self> {
            Arc::new(Self {
                answer,
                after,
                asked_at: Mutex::new(None),
                withdrawn: Mutex::new(Vec::new()),
            })
        }
        fn asked_at(&self) -> Option<Instant> {
            *self.asked_at.lock().unwrap()
        }
        fn withdrawn(&self) -> Vec<String> {
            self.withdrawn.lock().unwrap().clone()
        }
    }

    impl PhoneApprover for FakePhone {
        fn approve(&self, _req: ApprovalRequest) -> BoxFuture<PhoneAnswer> {
            *self.asked_at.lock().unwrap() = Some(Instant::now());
            let (answer, after) = (self.answer.clone(), self.after);
            Box::pin(async move {
                tokio::time::sleep(after).await;
                answer
            })
        }
        fn withdraw(&self, id: &str) {
            self.withdrawn.lock().unwrap().push(id.to_string());
        }
        fn is_paired(&self) -> bool {
            true
        }
    }

    /// A dialog answering `answer` after `after` (`None`: never answers
    /// and waits out its timeout, then denies).
    struct FakeDialog {
        answer: Option<(bool, Duration)>,
        opened_at: Mutex<Option<(Instant, Duration)>>,
        closed: Mutex<bool>,
    }

    impl FakeDialog {
        fn new(answer: Option<(bool, Duration)>) -> Self {
            Self {
                answer,
                opened_at: Mutex::new(None),
                closed: Mutex::new(false),
            }
        }
        fn opened_at(&self) -> Option<(Instant, Duration)> {
            *self.opened_at.lock().unwrap()
        }
        fn closed(&self) -> bool {
            *self.closed.lock().unwrap()
        }
    }

    impl ConfirmDialog for FakeDialog {
        fn open(&self, timeout: Duration, _phone_asked: bool) -> BoxFuture<bool> {
            *self.opened_at.lock().unwrap() = Some((Instant::now(), timeout));
            let answer = self.answer;
            Box::pin(async move {
                match answer {
                    Some((a, after)) if after < timeout => {
                        tokio::time::sleep(after).await;
                        a
                    }
                    _ => {
                        tokio::time::sleep(timeout).await;
                        false
                    }
                }
            })
        }
        fn close(&self) {
            *self.closed.lock().unwrap() = true;
        }
    }

    fn probe(locked: Option<bool>) -> LockProbe {
        Arc::new(move || Box::pin(async move { locked }))
    }

    fn req() -> ApprovalRequest {
        ApprovalRequest {
            id: new_request_id(),
            key_blob: vec![1],
            key_name: "k".into(),
            data: vec![2],
            flags: 0,
            binds: Vec::new(),
            caller: None,
            agent: "desk".into(),
            hints: BTreeMap::new(),
            ttl_s: 90,
        }
    }

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[tokio::test(start_paused = true)]
    async fn delay_zero_asks_both_at_once_and_the_phone_wins() {
        let start = Instant::now();
        let phone = FakePhone::new(PhoneAnswer::Approved, S(5));
        let dialog = FakeDialog::new(None);
        assert!(race(req(), phone.clone(), &dialog, S(0), probe(Some(false))).await);
        assert_eq!(phone.asked_at(), Some(start));
        assert_eq!(dialog.opened_at().unwrap().0, start);
        assert!(dialog.closed(), "the dialog is withdrawn when the phone wins");
        assert!(phone.withdrawn().is_empty(), "an answered request needs no withdraw");
        assert_eq!(Instant::now() - start, S(5));
    }

    #[tokio::test(start_paused = true)]
    async fn the_dialog_answering_first_withdraws_the_phone() {
        let phone = FakePhone::new(PhoneAnswer::Approved, S(20));
        let dialog = FakeDialog::new(Some((true, S(3))));
        let r = req();
        let id = r.id.clone();
        assert!(race(r, phone.clone(), &dialog, S(0), probe(Some(false))).await);
        assert_eq!(phone.withdrawn(), vec![id]);
        assert!(!dialog.closed(), "a dialog that answered closed itself");
    }

    #[tokio::test(start_paused = true)]
    async fn the_phone_waits_for_the_delay() {
        let start = Instant::now();
        let phone = FakePhone::new(PhoneAnswer::Approved, S(1));
        let dialog = FakeDialog::new(None);
        assert!(race(req(), phone.clone(), &dialog, S(10), probe(Some(false))).await);
        assert_eq!(phone.asked_at(), Some(start + S(10)));
    }

    #[tokio::test(start_paused = true)]
    async fn answered_at_the_desk_within_the_delay_never_reaches_the_phone() {
        let phone = FakePhone::new(PhoneAnswer::Approved, S(1));
        let dialog = FakeDialog::new(Some((true, S(4))));
        assert!(race(req(), phone.clone(), &dialog, S(10), probe(Some(false))).await);
        assert_eq!(phone.asked_at(), None);
        assert!(phone.withdrawn().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_deny_on_either_side_denies() {
        let phone = FakePhone::new(PhoneAnswer::Denied("user".into()), S(2));
        let dialog = FakeDialog::new(Some((true, S(30))));
        assert!(!race(req(), phone, &dialog, S(0), probe(Some(false))).await);
        assert!(dialog.closed());

        let phone = FakePhone::new(PhoneAnswer::Approved, S(30));
        let dialog = FakeDialog::new(Some((false, S(2))));
        assert!(!race(req(), phone, &dialog, S(0), probe(Some(false))).await);
    }

    #[tokio::test(start_paused = true)]
    async fn locked_screen_asks_the_phone_only_and_at_once() {
        let start = Instant::now();
        let phone = FakePhone::new(PhoneAnswer::Approved, S(15));
        let dialog = FakeDialog::new(None);
        assert!(race(req(), phone.clone(), &dialog, S(30), probe(Some(true))).await);
        assert_eq!(phone.asked_at(), Some(start), "no delay behind a locked screen");
        assert_eq!(dialog.opened_at(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn unlocking_brings_the_dialog_back() {
        let start = Instant::now();
        let locked = Arc::new(Mutex::new(true));
        let l2 = locked.clone();
        let probe: LockProbe = Arc::new(move || {
            let v = *l2.lock().unwrap();
            Box::pin(async move { Some(v) })
        });
        let phone = FakePhone::new(PhoneAnswer::Approved, S(80));
        let dialog = FakeDialog::new(Some((true, S(1))));
        let unlock = {
            let locked = locked.clone();
            async move {
                tokio::time::sleep(S(9)).await;
                *locked.lock().unwrap() = false;
            }
        };
        let (approved, ()) = tokio::join!(race(req(), phone.clone(), &dialog, S(0), probe), unlock);
        assert!(approved);
        let (opened, timeout) = dialog.opened_at().unwrap();
        assert!(opened >= start + S(9) && opened <= start + S(11));
        assert_eq!(timeout, PHONE_TIMEOUT - (opened - start), "the dialog gets what is left");
        assert_eq!(phone.withdrawn().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unreachable_phone_falls_back_to_the_dialog() {
        // Locked: the dialog comes up as soon as the phone gives up.
        let phone = FakePhone::new(PhoneAnswer::Unavailable("relay down".into()), S(1));
        let dialog = FakeDialog::new(Some((true, S(2))));
        assert!(race(req(), phone, &dialog, S(0), probe(Some(true))).await);
        assert!(dialog.opened_at().is_some());

        // Unlocked: the dialog's answer still decides.
        let phone = FakePhone::new(PhoneAnswer::Unavailable("relay down".into()), S(1));
        let dialog = FakeDialog::new(Some((false, S(5))));
        assert!(!race(req(), phone, &dialog, S(0), probe(Some(false))).await);
    }

    #[tokio::test(start_paused = true)]
    async fn nobody_answering_denies_at_ninety_seconds() {
        let start = Instant::now();
        let phone = FakePhone::new(PhoneAnswer::Approved, S(500));
        let dialog = FakeDialog::new(None);
        assert!(!race(req(), phone.clone(), &dialog, S(0), probe(Some(false))).await);
        assert_eq!(Instant::now() - start, PHONE_TIMEOUT);
        assert_eq!(phone.withdrawn().len(), 1);
        assert!(dialog.closed() || dialog.opened_at().unwrap().1 == PHONE_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_race_withdraws_both_prompts() {
        // What happens when the agent stops: SignGuard drops the future.
        let phone = FakePhone::new(PhoneAnswer::Approved, S(60));
        let dialog = FakeDialog::new(None);
        let (tx, rx) = oneshot::channel::<()>();
        tokio::select! {
            _ = race(req(), phone.clone(), &dialog, S(0), probe(Some(false))) => unreachable!(),
            _ = async { tokio::time::sleep(S(3)).await; let _ = tx.send(()); let _ = rx.await; } => {}
        }
        assert_eq!(phone.withdrawn().len(), 1);
        assert!(dialog.closed());
    }

    #[tokio::test(start_paused = true)]
    async fn no_phone_is_the_dialog_alone() {
        let dialog = FakeDialog::new(Some((true, S(2))));
        assert!(race(req(), Arc::new(NoPhone), &dialog, S(0), probe(Some(true))).await);
    }

    #[test]
    fn request_ids_are_32_hex_digits_and_fresh() {
        let (a, b) = (new_request_id(), new_request_id());
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
