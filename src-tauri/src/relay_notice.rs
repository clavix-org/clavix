//! A desktop notification when a hosted relay refuses a phone request for
//! a reason the user has to act on (no subscription, too many machines).
//!
//! Such a refusal happens in the middle of an SSH login: `ssh` only says
//! that the agent refused, and Clavix usually sits in the tray. The
//! settings show the reason next to the pairing (`RelayRefusal` in the
//! phone statuses), but nobody opens the settings without a hint.
//!
//! Linux only for now, over `org.freedesktop.Notifications`: clicking the
//! notification raises the window and opens the SSH settings. Elsewhere
//! nothing is shown; the settings and the log still say why.
//!
//! One notification per pairing and per change of state, and at most one
//! an hour while the state lasts: a tool retrying a login in a loop must
//! not fill the notification list.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tauri::AppHandle;

use crate::commands::phone::RelayRefusal;

/// Asks the front end to open the SSH settings (now, or once the vault is
/// unlocked).
pub const EVENT_OPEN_SSH_SETTINGS: &str = "clavix:open-ssh-settings";

/// How long the same refusal stays quiet after a notification.
const REPEAT_AFTER: Duration = Duration::from_secs(60 * 60);

static APP: OnceLock<AppHandle> = OnceLock::new();
static LOCALE: Mutex<String> = Mutex::new(String::new());

/// Called once at setup: the requests that get refused run far from any
/// Tauri command, in the agent's tasks.
pub fn init(app: &AppHandle) {
    let _ = APP.set(app.clone());
}

/// The interface language, as the tray has it (`set_tray_locale`).
pub fn set_locale(locale: &str) {
    *LOCALE.lock() = locale.to_string();
}

/// What one pairing was last notified about.
pub struct Notified(Mutex<Option<(RelayRefusal, Instant)>>);

impl Notified {
    pub const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// A request got through, or the pairing changed: the next refusal is
    /// news again.
    pub fn reset(&self) {
        *self.0.lock() = None;
    }

    /// Whether `refusal`, seen at `now`, deserves a notification; if so,
    /// it is recorded as shown.
    fn due(&self, refusal: RelayRefusal, now: Instant) -> bool {
        let mut last = self.0.lock();
        let quiet = last.is_some_and(|(shown, at)| {
            shown == refusal && now.saturating_duration_since(at) < REPEAT_AFTER
        });
        if !quiet {
            *last = Some((refusal, now));
        }
        !quiet
    }
}

/// The relay refused a request of the pairing `notified` belongs to.
pub fn refused(notified: &Notified, refusal: RelayRefusal) {
    if !notified.due(refusal, Instant::now()) {
        return;
    }
    let Some(app) = APP.get() else {
        return;
    };
    let text = text(&LOCALE.lock(), refusal);
    show(app.clone(), text);
}

struct Text {
    summary: &'static str,
    body: &'static str,
    /// Label of the notification's action, where the server shows one.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    open: &'static str,
}

fn text(locale: &str, refusal: RelayRefusal) -> Text {
    use RelayRefusal::{MachineLimit, SubscriptionRequired};
    match (locale, refusal) {
        ("en", SubscriptionRequired) => Text {
            summary: "Clavix: a subscription is required to approve from your phone",
            body: "Open Clavix Approve on the iPhone to subscribe or renew.",
            open: "Open the settings",
        },
        ("en", MachineLimit) => Text {
            summary: "Clavix: machine limit reached",
            body: "Your subscription already covers as many machines as it allows.",
            open: "Open the settings",
        },
        // "fr" and any unknown locale share the French default, as the
        // tray does.
        (_, SubscriptionRequired) => Text {
            summary: "Clavix : abonnement requis pour approuver depuis le téléphone",
            body: "Ouvrez Clavix Approve sur l'iPhone pour vous abonner ou renouveler votre \
                   abonnement.",
            open: "Ouvrir les préférences",
        },
        (_, MachineLimit) => Text {
            summary: "Clavix : limite de machines atteinte",
            body: "Votre abonnement couvre déjà le nombre maximal de machines.",
            open: "Ouvrir les préférences",
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn show(_app: AppHandle, text: Text) {
    // No notification on this platform yet; the settings carry the reason.
    let _ = (text.summary, text.body);
}

#[cfg(target_os = "linux")]
fn show(app: AppHandle, text: Text) {
    tauri::async_runtime::spawn(async move {
        match linux::notify(&text).await {
            Ok(true) => {
                use tauri::Emitter;
                crate::commands::tray::raise_main_window(&app);
                let _ = app.emit(EVENT_OPEN_SSH_SETTINGS, ());
            }
            Ok(false) => {}
            Err(e) => eprintln!("[clavix phone] no desktop notification: {e}"),
        }
    });
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::time::Duration;

    use futures_util::StreamExt;
    use zbus::message::Type as MessageType;
    use zbus::zvariant::Variant;
    use zbus::MessageStream;

    use super::Text;

    const DEST: &str = "org.freedesktop.Notifications";
    const PATH: &str = "/org/freedesktop/Notifications";
    /// The action a click on the notification itself invokes.
    const DEFAULT_ACTION: &str = "default";
    /// How long a click is waited for. The notification stays in the
    /// desktop's list after that; a click then does nothing.
    const CLICK_WINDOW: Duration = Duration::from_secs(10 * 60);

    /// Show the notification; `Ok(true)` once the user clicked it.
    pub async fn notify(text: &Text) -> Result<bool, String> {
        let conn = crate::dbus::session()
            .await
            .map_err(|e| format!("session bus unavailable: {e}"))?;

        // Subscribe before the call: the id the signals carry is only
        // known from its reply.
        let rule = format!("type='signal',sender='{DEST}',interface='{DEST}'");
        conn.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "AddMatch",
            &(rule.as_str(),),
        )
        .await
        .map_err(|e| e.to_string())?;
        let mut stream = MessageStream::from(&conn);

        let mut hints: HashMap<&str, Variant<'_>> = HashMap::new();
        // Groups it under Clavix, with its icon, in the notification list.
        hints.insert("desktop-entry", Variant::from("clavix"));
        let actions = vec![DEFAULT_ACTION, text.open];
        let reply = conn
            .call_method(
                Some(DEST),
                PATH,
                Some(DEST),
                "Notify",
                &(
                    "Clavix",
                    0u32,
                    "clavix",
                    text.summary,
                    text.body,
                    actions,
                    hints,
                    -1i32,
                ),
            )
            .await
            .map_err(|e| format!("notification service unavailable: {e}"))?;
        let id: u32 = reply.body().deserialize().map_err(|e| e.to_string())?;

        let clicked = async {
            while let Some(msg) = stream.next().await {
                let Ok(msg) = msg else { continue };
                let header = msg.header();
                if header.message_type() != MessageType::Signal {
                    continue;
                }
                match header.member().map(|m| m.as_str()) {
                    Some("ActionInvoked") => {
                        if let Ok((of, _action)) = msg.body().deserialize::<(u32, String)>() {
                            if of == id {
                                return true;
                            }
                        }
                    }
                    Some("NotificationClosed") => {
                        if let Ok((of, _reason)) = msg.body().deserialize::<(u32, u32)>() {
                            if of == id {
                                return false;
                            }
                        }
                    }
                    _ => {}
                }
            }
            false
        };
        Ok(tokio::time::timeout(CLICK_WINDOW, clicked)
            .await
            .unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use RelayRefusal::{MachineLimit, SubscriptionRequired};

    #[test]
    fn a_refusal_is_notified_once_per_state_and_at_most_hourly() {
        let notified = Notified::new();
        let start = Instant::now();
        let after = |minutes: u64| start + Duration::from_secs(60 * minutes);

        assert!(notified.due(SubscriptionRequired, start));
        // ssh retried, the agent failed again: nothing new to say.
        assert!(!notified.due(SubscriptionRequired, after(1)));
        assert!(!notified.due(SubscriptionRequired, after(59)));
        // Still unpaid an hour later.
        assert!(notified.due(SubscriptionRequired, after(61)));
        assert!(!notified.due(SubscriptionRequired, after(62)));
        // Another reason is news.
        assert!(notified.due(MachineLimit, after(63)));
        assert!(!notified.due(MachineLimit, after(64)));
        // A request got through in between: the next refusal is news.
        notified.reset();
        assert!(notified.due(MachineLimit, after(65)));
    }

    #[test]
    fn the_notification_is_worded_in_the_interface_language() {
        assert!(text("en", SubscriptionRequired)
            .summary
            .contains("subscription is required"));
        assert!(text("fr", SubscriptionRequired)
            .summary
            .contains("abonnement requis"));
        // Before the front end said which: French, as the tray.
        assert!(text("", MachineLimit)
            .summary
            .contains("limite de machines"));
        assert!(text("en", MachineLimit).body.contains("machines"));
    }
}
