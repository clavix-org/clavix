//! Pairing a phone that approves SSH-agent signatures, and loading that
//! pairing while the vault is unlocked.
//!
//! The pairing (a Clavix Approve channel: relay, bearer token, channel
//! keys, paired devices) lives in `session.json`, encrypted with the user
//! key, so it is readable only while the vault is unlocked — the only
//! time there are keys to approve anything with. It is per device and
//! never reaches the Vaultwarden server.
//!
//! The commands exist in every build so the front end has one surface;
//! without the `phone-approval` feature they report the feature as
//! unavailable.

use serde::Serialize;
use tauri::State;
use ts_rs::TS;

use crate::state::AppState;
use clavix_core::error::{Error, Result};

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PhoneStatus {
    /// This build can talk to a relay (`phone-approval` feature).
    pub available: bool,
    /// A pairing is loaded (the vault is unlocked and a phone is paired).
    pub paired: bool,
    /// Names the paired devices gave themselves.
    pub devices: Vec<String>,
    /// Relay of the pairing.
    pub relay: Option<String>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PhonePairOffer {
    /// The code to type in the phone (`cva1-…`, 15 minutes, works once).
    pub code: String,
    /// `<relay>/#<code>`: opens the relay's page with the code filled in.
    pub link: String,
    /// The link as a QR code, an SVG document.
    pub qr_svg: String,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PhonePairCandidate {
    /// Six digits the phone shows too; pairing is kept only if they match.
    pub digits: String,
    pub device_name: String,
}

#[cfg_attr(feature = "phone-approval", allow(dead_code))]
fn unavailable() -> Error {
    Error::Storage {
        reason: "this build of Clavix cannot approve on a phone".into(),
    }
}

#[cfg(feature = "phone-approval")]
mod imp {
    use std::sync::Arc;
    use std::time::Duration;

    use parking_lot::Mutex;
    use tokio::sync::Notify;

    use super::*;
    use crate::phone_approval::{NoPhone, PhoneApprover};
    use crate::phone_relay::{ApproveChannel, ApproveOffer, PairedDevice, RelayPhone};
    use clavix_approve_core::relay::RelayError;
    use clavix_core::crypto::{decrypt_name, encrypt_string};
    use clavix_core::store;

    /// How long `phone_pair_wait` waits: just under the relay's 15 min.
    const PAIR_WAIT: Duration = Duration::from_secs(14 * 60);

    /// A pairing in progress. One at a time.
    struct Pairing {
        offer: Arc<ApproveOffer>,
        /// The relay the offer is open on, to name it when it goes away.
        relay: String,
        /// The channel being extended, for a second phone.
        existing: Option<ApproveChannel>,
        candidate: Option<PairedDevice>,
        cancel: Arc<Notify>,
    }

    static PAIRING: Mutex<Option<Pairing>> = Mutex::new(None);
    /// The loaded channel, kept for status, adding a device and revoking.
    /// Cleared with the approver when the vault locks.
    static CHANNEL: Mutex<Option<ApproveChannel>> = Mutex::new(None);

    fn relay_error(e: impl std::fmt::Display) -> Error {
        Error::InvalidResponse {
            reason: format!("phone relay: {e}"),
        }
    }

    /// The error of a call to the relay at `relay`. One that never got an
    /// answer (DNS, connection refused, TLS, timeout) is reported as the
    /// relay being unreachable, with its address; anything else is what
    /// the relay answered.
    ///
    /// The pairing calls of `clavix-approve-core` return their errors as
    /// text, so a transport failure is recognised by how the crate words
    /// `RelayError::Transport`. The wording is asked from the crate rather
    /// than copied here, so that a crate update cannot silently undo this.
    pub(crate) fn relay_call_error(relay: &str, e: impl std::fmt::Display) -> Error {
        let text = e.to_string();
        let unreachable = RelayError::Transport(String::new()).to_string();
        match text.strip_prefix(&unreachable) {
            Some(cause) => Error::RelayUnreachable {
                url: relay.to_string(),
                cause: cause.to_string(),
            },
            None => relay_error(text),
        }
    }

    /// Run `f` with the user key, which exists only while unlocked (and
    /// is deliberately not `Clone`).
    fn with_user_key<T>(
        state: &AppState,
        f: impl FnOnce(&clavix_core::crypto::SymmetricKey) -> Result<T>,
    ) -> Result<T> {
        let guard = state.session.lock();
        let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        f(&session.user_key)
    }

    fn save_channel(state: &AppState, channel: Option<&ApproveChannel>) -> Result<()> {
        let mut persisted = store::load_session()?.ok_or(Error::NotAuthenticated)?;
        persisted.phone_approval = match channel {
            Some(c) => {
                let json = serde_json::to_string(c).map_err(|e| Error::Storage {
                    reason: format!("encode phone pairing: {e}"),
                })?;
                Some(with_user_key(state, |k| encrypt_string(&json, k))?)
            }
            None => None,
        };
        store::save_session(&persisted)
    }

    fn install(state: &AppState, channel: Option<ApproveChannel>) {
        let approver: Arc<dyn PhoneApprover> = match channel.as_ref().map(RelayPhone::new) {
            Some(Ok(phone)) => phone,
            Some(Err(e)) => {
                eprintln!("[clavix phone] stored pairing unusable: {e}");
                Arc::new(NoPhone)
            }
            None => Arc::new(NoPhone),
        };
        *state.phone_approver.lock() = approver;
        *CHANNEL.lock() = channel;
    }

    /// Load the stored pairing, if any, now that the vault is unlocked.
    pub fn load(state: &AppState) {
        if CHANNEL.lock().is_some() {
            return;
        }
        let Some(enc) = store::load_session()
            .ok()
            .flatten()
            .and_then(|s| s.phone_approval)
        else {
            return;
        };
        let Ok(decrypted) = with_user_key(state, |k| Ok(decrypt_name(&enc, k).ok())) else {
            return; // locked again meanwhile
        };
        let channel = decrypted.and_then(|json| serde_json::from_str::<ApproveChannel>(&json).ok());
        if channel.is_none() {
            eprintln!("[clavix phone] stored pairing could not be read; pair again");
        }
        install(state, channel);
    }

    /// Drop the pairing from memory (the vault locked).
    pub fn unload(state: &AppState) {
        if let Some(p) = PAIRING.lock().take() {
            p.cancel.notify_waiters();
        }
        install(state, None);
    }

    pub fn status() -> PhoneStatus {
        let channel = CHANNEL.lock();
        PhoneStatus {
            available: true,
            paired: channel.as_ref().is_some_and(|c| !c.devices.is_empty()),
            devices: channel
                .as_ref()
                .map(|c| c.devices.iter().map(|d| d.name().to_string()).collect())
                .unwrap_or_default(),
            relay: channel.as_ref().map(|c| c.relay.clone()),
        }
    }

    /// The pairing link as a QR code, an SVG document (no network).
    pub(crate) fn qr_svg(link: &str) -> Result<String> {
        let code = qrcode::QrCode::new(link.as_bytes()).map_err(|e| Error::Storage {
            reason: format!("QR code: {e}"),
        })?;
        Ok(code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(200, 200)
            .quiet_zone(true)
            .build())
    }

    pub async fn pair_start(
        state: &AppState,
        relay: String,
        enroll_secret: String,
        label: String,
    ) -> Result<PhonePairOffer> {
        with_user_key(state, |_| Ok(()))?; // only while unlocked: stored encrypted
        let existing = CHANNEL.lock().clone();
        let relay = match &existing {
            Some(c) => c.relay.clone(),
            None => relay.trim().to_string(),
        };
        let offer = match &existing {
            // One more phone on the same channel (and relay).
            Some(c) => ApproveOffer::add_device(c).await,
            None => ApproveOffer::open(&relay, enroll_secret.trim(), label.trim()).await,
        }
        .map_err(|e| relay_call_error(&relay, e))?;
        let link = offer.link();
        let out = PhonePairOffer {
            code: offer.code().to_string(),
            qr_svg: qr_svg(&link)?,
            link,
        };
        if let Some(old) = PAIRING.lock().replace(Pairing {
            offer: Arc::new(offer),
            relay,
            existing,
            candidate: None,
            cancel: Arc::new(Notify::new()),
        }) {
            old.cancel.notify_waiters();
        }
        Ok(out)
    }

    pub async fn pair_wait() -> Result<PhonePairCandidate> {
        let (offer, relay, cancel) = {
            let slot = PAIRING.lock();
            let p = slot
                .as_ref()
                .ok_or_else(|| relay_error("no pairing in progress"))?;
            (p.offer.clone(), p.relay.clone(), p.cancel.clone())
        };
        let paired = tokio::select! {
            r = offer.wait(PAIR_WAIT) => r.map_err(|e| relay_call_error(&relay, e))?,
            _ = cancel.notified() => return Err(relay_error("pairing cancelled")),
        };
        drop(offer);
        let out = PhonePairCandidate {
            digits: paired.digits.clone(),
            device_name: paired.device.name().to_string(),
        };
        if let Some(p) = PAIRING.lock().as_mut() {
            p.candidate = Some(paired);
        }
        Ok(out)
    }

    /// The user saw the same digits on both screens: keep the device.
    pub fn pair_confirm(state: &AppState) -> Result<PhoneStatus> {
        let pairing = PAIRING
            .lock()
            .take()
            .ok_or_else(|| relay_error("no pairing in progress"))?;
        let device = pairing
            .candidate
            .ok_or_else(|| relay_error("no phone answered yet"))?;
        let channel = match pairing.existing {
            Some(mut c) => {
                c.devices.push(device.device);
                c
            }
            None => Arc::try_unwrap(pairing.offer)
                .map_err(|_| relay_error("pairing still in use"))?
                .into_channel(device.device),
        };
        save_channel(state, Some(&channel))?;
        install(state, Some(channel));
        Ok(status())
    }

    /// Digits differ, or the user gave up. A device that answered is not
    /// kept; on a new channel it stays on the relay unused until it
    /// expires (the relay forgets unpaired channels).
    pub fn pair_cancel() {
        if let Some(p) = PAIRING.lock().take() {
            p.cancel.notify_waiters();
        }
    }

    /// Revoke the pairing on the relay and forget it here. Forgotten
    /// locally even when the relay cannot be reached.
    pub async fn forget(state: &AppState) -> Result<PhoneStatus> {
        let channel = CHANNEL.lock().clone();
        if let Some(c) = &channel {
            if let Err(e) = c.revoke().await {
                eprintln!(
                    "[clavix phone] revoking on the relay failed (forgotten here anyway): {e}"
                );
            }
        }
        save_channel(state, None)?;
        install(state, None);
        Ok(status())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::phone_relay::ApproveOffer;
        use clavix_approve_core::requester as rq;

        const RELAY: &str = "https://relay.example";

        #[test]
        fn a_relay_that_never_answered_is_unreachable_not_an_invalid_response() {
            // Typed, as the revoke calls return it; inside the requester's
            // error; and as the text the pairing calls reduce it to.
            let transport = RelayError::Transport("error sending request".into());
            let as_text = transport.to_string();
            let errors: [Box<dyn std::fmt::Display>; 3] = [
                Box::new(transport.clone()),
                Box::new(rq::Error::from(transport)),
                Box::new(rq::Error::from(as_text)),
            ];
            for e in errors {
                match relay_call_error(RELAY, e) {
                    Error::RelayUnreachable { url, cause } => {
                        assert_eq!(url, RELAY);
                        assert_eq!(cause, "error sending request");
                    }
                    other => panic!("expected RelayUnreachable, got {other:?}"),
                }
            }
        }

        #[test]
        fn what_the_relay_answered_is_still_an_invalid_response() {
            let answers: [Box<dyn std::fmt::Display>; 4] = [
                Box::new(RelayError::Status(503)),
                Box::new(RelayError::Protocol("not JSON".into())),
                Box::new(rq::Error::Revoked),
                Box::new("nobody entered the pairing code in time"),
            ];
            for e in answers {
                let text = e.to_string();
                match relay_call_error(RELAY, e) {
                    Error::InvalidResponse { reason } => assert!(reason.ends_with(&text)),
                    other => panic!("expected InvalidResponse, got {other:?}"),
                }
            }
        }

        /// Nothing listens on the port: the real crate, the real error.
        #[tokio::test]
        async fn pairing_with_a_phone_relay_that_refuses_connections_says_unreachable() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let relay = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            drop(listener);
            let Err(e) = ApproveOffer::open(&relay, "secret", "desk").await else {
                panic!("a closed port cannot have opened a channel");
            };
            assert!(matches!(
                relay_call_error(&relay, e),
                Error::RelayUnreachable { url, .. } if url == relay
            ));
        }
    }
}

#[cfg(feature = "phone-approval")]
pub(crate) use imp::{qr_svg, relay_call_error};

/// Load the stored pairing (vault just unlocked). No-op without the
/// feature.
pub(crate) fn load_paired_phone(_state: &AppState) {
    #[cfg(feature = "phone-approval")]
    imp::load(_state);
}

/// Forget the loaded pairing (vault locked). The stored, encrypted copy
/// stays.
pub(crate) fn unload_paired_phone(state: &AppState) {
    #[cfg(feature = "phone-approval")]
    imp::unload(state);
    #[cfg(not(feature = "phone-approval"))]
    {
        *state.phone_approver.lock() = std::sync::Arc::new(crate::phone_approval::NoPhone);
    }
}

#[tauri::command]
pub fn phone_status() -> PhoneStatus {
    #[cfg(feature = "phone-approval")]
    return imp::status();
    #[cfg(not(feature = "phone-approval"))]
    PhoneStatus {
        available: false,
        paired: false,
        devices: Vec::new(),
        relay: None,
    }
}

#[tauri::command]
pub async fn phone_pair_start(
    _state: State<'_, AppState>,
    _relay: String,
    _enroll_secret: String,
    _label: String,
) -> Result<PhonePairOffer> {
    #[cfg(feature = "phone-approval")]
    return imp::pair_start(&_state, _relay, _enroll_secret, _label).await;
    #[cfg(not(feature = "phone-approval"))]
    Err(unavailable())
}

#[tauri::command]
pub async fn phone_pair_wait() -> Result<PhonePairCandidate> {
    #[cfg(feature = "phone-approval")]
    return imp::pair_wait().await;
    #[cfg(not(feature = "phone-approval"))]
    Err(unavailable())
}

#[tauri::command]
pub fn phone_pair_confirm(_state: State<'_, AppState>) -> Result<PhoneStatus> {
    #[cfg(feature = "phone-approval")]
    return imp::pair_confirm(&_state);
    #[cfg(not(feature = "phone-approval"))]
    Err(unavailable())
}

#[tauri::command]
pub fn phone_pair_cancel() {
    #[cfg(feature = "phone-approval")]
    imp::pair_cancel();
}

#[tauri::command]
pub async fn phone_forget(_state: State<'_, AppState>) -> Result<PhoneStatus> {
    #[cfg(feature = "phone-approval")]
    return imp::forget(&_state).await;
    #[cfg(not(feature = "phone-approval"))]
    Err(unavailable())
}
