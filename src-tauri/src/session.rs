//! Where this app's `AppState` meets the engine's session slots.
//!
//! `clavix_core::services::auth` operates on the two mutexes it needs —
//! the session and the pending-2FA slot — and knows nothing about the
//! tray flags or the SSH agent that share the struct with them. These
//! wrappers hand it the right field so every command can keep passing
//! `&state`, and so the auto-lock bookkeeping that only exists on this
//! side stays attached to the calls that imply a live user.

use std::collections::HashMap;

use clavix_core::api::VaultwardenClient;
use clavix_core::crypto::SymmetricKey;
use clavix_core::error::Result;
use clavix_core::models::{SyncResponse, TokenSet};
use clavix_core::services::auth as core_auth;
use clavix_core::session::{PendingTwoFactor, SessionOrigin};
use rsa::RsaPrivateKey;

use crate::state::{mark_activity, AppState};

tokio::task_local! {
    /// Set for the length of a request nobody at the keyboard made.
    static UNATTENDED: ();
}

/// Run `request` without it counting as a sign of the user.
///
/// For the command line (`cli_server`): its requests reach the same
/// commands as the window's, and every one of those passes through
/// `ensure_fresh_tokens`. A script calling `clavix item …` from a timer
/// proves that a timer is running, not that anyone is there, and must not
/// hold the auto-lock off: the same reasoning as `mark_activity`'s note on
/// polled commands.
pub async fn unattended<F: std::future::Future>(request: F) -> F::Output {
    UNATTENDED.scope((), request).await
}

/// Refresh the access token if it is close to expiring, and record that
/// the user is still around (unless the request is [`unattended`]).
///
/// `mark_activity` lives here rather than in the engine because it feeds
/// the auto-lock watchdog, which is a desktop concern — but it belongs on
/// this call and not at the call sites: every command that reaches the
/// server goes through here, and a `mark_activity` that has to be
/// remembered separately is one that eventually isn't.
pub async fn ensure_fresh_tokens(state: &AppState) -> Result<()> {
    if UNATTENDED.try_with(|_| ()).is_err() {
        mark_activity(state);
    }
    core_auth::ensure_fresh_tokens(&state.session).await
}

pub fn store_session(
    state: &AppState,
    client: VaultwardenClient,
    tokens: TokenSet,
    user_key: SymmetricKey,
    private_key: Option<RsaPrivateKey>,
) {
    core_auth::store_session(&state.session, client, tokens, user_key, private_key);
    unlocked(state);
}

/// The vault is unlocked: the locked-vault agent, serving phone keys in
/// its absence, stops (whether or not the vault agent starts again).
fn unlocked(state: &AppState) {
    crate::commands::phone_sign::stop_locked_agent_sync(state);
}

/// Park a vault that has no server behind it — an unlock that could
/// not reach the server, or an encrypted export file opened directly.
pub fn store_standalone_session(
    state: &AppState,
    origin: SessionOrigin,
    user_key: SymmetricKey,
    private_key: Option<RsaPrivateKey>,
    org_keys: HashMap<String, SymmetricKey>,
    vault: Option<SyncResponse>,
) {
    core_auth::store_standalone_session(
        &state.session,
        origin,
        user_key,
        private_key,
        org_keys,
        vault,
    );
    unlocked(state);
}

pub fn set_pending_two_factor(state: &AppState, pending: PendingTwoFactor) {
    core_auth::set_pending_two_factor(&state.pending_2fa, pending);
}

pub fn clear_pending_two_factor(state: &AppState) {
    core_auth::clear_pending_two_factor(&state.pending_2fa);
}

pub fn clear_pending_two_factor_if_stale(state: &AppState) {
    core_auth::clear_pending_two_factor_if_stale(&state.pending_2fa);
}

pub fn with_pending_two_factor<R>(
    state: &AppState,
    f: impl FnOnce(&PendingTwoFactor) -> Result<R>,
) -> Result<R> {
    core_auth::with_pending_two_factor(&state.pending_2fa, f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// A window command proves someone is there; a command-line request
    /// does not, or a script on a timer would hold the auto-lock off.
    #[tokio::test]
    async fn only_an_attended_request_counts_as_activity() {
        let state = AppState::default();
        let long_ago = Instant::now() - Duration::from_secs(3600);

        *state.last_activity.lock() = long_ago;
        // No session: the call fails, after the bookkeeping under test.
        let _ = unattended(ensure_fresh_tokens(&state)).await;
        assert_eq!(*state.last_activity.lock(), long_ago);

        let _ = ensure_fresh_tokens(&state).await;
        assert!(*state.last_activity.lock() > long_ago);
    }
}
