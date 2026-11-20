//! Whether the relay of each phone pairing in use answers, for the
//! toolbar's relay indicator.
//!
//! The relay keeps no connection open: Clavix contacts it once per
//! request (an SSH signature to approve or to sign), so "connected" can
//! only mean "answers now". The probe is the relay's `/healthz`, which
//! takes no token and counts against no rate limit; nothing about the
//! pairing travels with it.

use serde::Serialize;
use ts_rs::TS;

use super::phone::RelayRefusal;

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct RelayHealth {
    /// The relay's base URL, as the pairing has it.
    pub relay: String,
    /// It answered `/healthz` just now.
    pub reachable: bool,
    /// It refused the last request of a pairing using it, for a reason
    /// the user has to act on (approve mode first, then sign mode).
    pub refusal: Option<RelayRefusal>,
}

/// One entry per distinct relay of the pairings in use (approve mode
/// while the vault is unlocked, sign mode whenever paired). Empty when no
/// phone is paired, and always without the `phone-approval` feature.
#[tauri::command]
pub async fn phone_relay_health() -> Vec<RelayHealth> {
    #[cfg(phone_approval)]
    {
        let in_use = in_use();
        let mut out = Vec::with_capacity(in_use.len());
        for (relay, refusal) in in_use {
            let reachable = imp::answers(&relay).await;
            out.push(RelayHealth {
                relay,
                reachable,
                refusal,
            });
        }
        out
    }
    #[cfg(not(phone_approval))]
    Vec::new()
}

/// The relays of the pairings in use, each with a refusal if one of its
/// pairings has one.
#[cfg(phone_approval)]
fn in_use() -> Vec<(String, Option<RelayRefusal>)> {
    let approve = super::phone::phone_status();
    let approve = approve
        .paired
        .then_some(approve.relay)
        .flatten()
        .map(|r| (r, approve.relay_refusal));
    let sign = super::phone_sign::imp::sign_dir()
        .and_then(|dir| super::phone_sign::imp::status(&dir, false))
        .ok()
        .filter(|s| s.paired)
        .and_then(|s| s.relay.map(|r| (r, s.relay_refusal)));
    merge(approve.into_iter().chain(sign))
}

/// Pairings on the same relay make one entry; the first refusal wins.
#[cfg_attr(not(phone_approval), allow(dead_code))]
fn merge(
    pairings: impl IntoIterator<Item = (String, Option<RelayRefusal>)>,
) -> Vec<(String, Option<RelayRefusal>)> {
    let mut out: Vec<(String, Option<RelayRefusal>)> = Vec::new();
    for (relay, refusal) in pairings {
        let key = relay.trim_end_matches('/');
        match out.iter_mut().find(|(r, _)| r.trim_end_matches('/') == key) {
            Some((_, seen)) => *seen = seen.or(refusal),
            None => out.push((relay, refusal)),
        }
    }
    out
}

#[cfg(phone_approval)]
mod imp {
    use std::time::Duration;

    /// Short: the indicator should turn red well before a login would
    /// time out against a relay that is gone.
    const TIMEOUT: Duration = Duration::from_secs(8);

    /// The relay answers `GET /healthz` with a success. Redirects are not
    /// followed, as for every relay call: the stored URL was checked at
    /// pairing (HTTPS, or a loopback address).
    pub(super) async fn answers(relay: &str) -> bool {
        let Ok(client) = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(TIMEOUT)
            .timeout(TIMEOUT)
            .build()
        else {
            return false;
        };
        let url = format!("{}/healthz", relay.trim_end_matches('/'));
        matches!(client.get(url).send().await, Ok(r) if r.status().is_success())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Read, Write};
        use std::net::TcpListener;

        /// A one-shot HTTP server on loopback answering `status_line`.
        fn serve_once(status_line: &'static str) -> String {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            std::thread::spawn(move || {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf);
                    let _ = write!(
                        s,
                        "{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                }
            });
            format!("http://{addr}")
        }

        #[tokio::test]
        async fn a_relay_answering_healthz_is_reachable() {
            assert!(answers(&serve_once("HTTP/1.1 200 OK")).await);
        }

        #[tokio::test]
        async fn an_error_or_a_redirect_is_not_reachable() {
            assert!(!answers(&serve_once("HTTP/1.1 502 Bad Gateway")).await);
            assert!(!answers(&serve_once("HTTP/1.1 302 Found")).await);
        }

        #[tokio::test]
        async fn a_relay_refusing_connections_is_not_reachable() {
            let port = TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            assert!(!answers(&format!("http://127.0.0.1:{port}")).await);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairings_on_one_relay_make_one_entry() {
        let merged = merge([
            ("https://a.example".to_string(), None),
            (
                "https://a.example/".to_string(),
                Some(RelayRefusal::MachineLimit),
            ),
            ("https://b.example".to_string(), None),
        ]);
        assert_eq!(
            merged,
            vec![
                (
                    "https://a.example".to_string(),
                    Some(RelayRefusal::MachineLimit)
                ),
                ("https://b.example".to_string(), None),
            ]
        );
    }
}
