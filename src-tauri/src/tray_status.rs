//! What the tray says about the vault and the SSH agent: a padlock on the
//! icon while the vault is locked, a green dot while the phone's agent
//! serves, and a menu that matches (no "Lock now" over a locked vault).
//!
//! The state is read, not pushed: a watcher (`spawn_watcher`) recomputes
//! it every second and touches the tray only when it changed. Locks,
//! unlocks, logouts and agent starts happen on a dozen paths (commands,
//! the auto-lock, the tray itself, spawned tasks); a missed notification
//! on one of them would leave the tray lying, which is the very failure
//! this exists to make visible. Each tick is two mutex reads while
//! unlocked, plus two small file reads while not.

use std::time::Duration;

use image::{Rgba, RgbaImage};
use parking_lot::Mutex;
use tauri::{AppHandle, Manager};

use crate::state::AppState;

/// What the tray shows. `agent` is the locked-vault agent: the phone's
/// keys served with no vault open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    /// No account and no phone-only setup: nothing to lock.
    NoAccount,
    Unlocked,
    Locked {
        agent: bool,
    },
    /// No vault at all, the phone's agent only.
    PhoneOnly {
        agent: bool,
    },
}

impl TrayState {
    pub fn padlock(self) -> bool {
        matches!(self, Self::Locked { .. })
    }

    pub fn dot(self) -> bool {
        matches!(
            self,
            Self::Locked { agent: true } | Self::PhoneOnly { agent: true }
        )
    }

    /// "Lock now" only makes sense over an open vault.
    pub fn can_lock(self) -> bool {
        self == Self::Unlocked
    }
}

/// The state as of now.
pub fn current(app: &AppHandle) -> TrayState {
    let state = app.state::<AppState>();
    if state.session.lock().is_some() {
        return TrayState::Unlocked;
    }
    let agent = state.locked_agent.lock().is_some();
    if crate::commands::app_mode::load() == crate::commands::app_mode::AppMode::PhoneOnly {
        return TrayState::PhoneOnly { agent };
    }
    match clavix_core::store::load_session() {
        Ok(Some(_)) => TrayState::Locked { agent },
        _ => TrayState::NoAccount,
    }
}

/// The status line at the top of the menu, also the tooltip after
/// "Clavix — ". `None`: no line.
pub fn status_label(state: TrayState, locale: &str) -> Option<&'static str> {
    let en = locale == "en";
    Some(match state {
        TrayState::NoAccount => return None,
        TrayState::Unlocked if en => "Vault unlocked",
        TrayState::Unlocked => "Coffre déverrouillé",
        TrayState::Locked { agent: true } if en => "Locked · the phone signs",
        TrayState::Locked { agent: true } => "Verrouillé · le téléphone signe",
        TrayState::Locked { agent: false } if en => "Locked · SSH agent stopped",
        TrayState::Locked { agent: false } => "Verrouillé · agent SSH arrêté",
        TrayState::PhoneOnly { agent: true } if en => "Phone only · the phone signs",
        TrayState::PhoneOnly { agent: true } => "Téléphone seul · le téléphone signe",
        TrayState::PhoneOnly { agent: false } if en => "Phone only · SSH agent stopped",
        TrayState::PhoneOnly { agent: false } => "Téléphone seul · agent SSH arrêté",
    })
}

/// The item that raises the window: it unlocks, over a locked vault.
pub fn open_label(state: TrayState, locale: &str) -> &'static str {
    match (state.padlock(), locale == "en") {
        (true, true) => "Unlock…",
        (true, false) => "Déverrouiller…",
        (false, true) => "Open Clavix",
        (false, false) => "Ouvrir Clavix",
    }
}

/// The colours of the marks, for an icon drawn in `ink` (the padlock's
/// body). The dot is green whatever the style: it means "serving".
const GREEN: Rgba<u8> = Rgba([34, 197, 94, 255]);
pub const CLEAR: Rgba<u8> = Rgba([0, 0, 0, 0]);

/// Draw the marks of `state` on a tray icon, each inside a one-unit ring
/// of `halo` so it reads at 16 px. `CLEAR` cuts the ring out of the logo,
/// right for a monochrome icon drawn in the panel's own colour; the
/// colour logo needs a light ring instead, or its dark padlock vanishes
/// on a dark panel. Drawn on a 32-unit grid scaled to the icon.
pub fn decorate(img: &mut RgbaImage, state: TrayState, ink: Rgba<u8>, halo: Rgba<u8>) {
    let scale = img.width() as f32 / 32.0;
    if state.padlock() {
        let shape = |x: f32, y: f32| padlock_at(x / scale, y / scale);
        stamp(img, &shape, ink, halo);
        // The keyhole, in the ring's colour.
        let keyhole = |x: f32, y: f32| {
            let (x, y) = (x / scale, y / scale);
            (23.5..25.5).contains(&x) && (23.0..27.0).contains(&y)
        };
        paint(img, &keyhole, halo);
    }
    if state.dot() {
        let shape = |x: f32, y: f32| {
            let (dx, dy) = (x / scale - 26.0, y / scale - 6.0);
            dx * dx + dy * dy <= 4.5 * 4.5
        };
        stamp(img, &shape, GREEN, halo);
    }
}

/// The padlock, bottom right of a 32-unit icon: a 13 × 10 body under a
/// shackle 9 wide and 2 thick.
fn padlock_at(x: f32, y: f32) -> bool {
    let body = (18.0..31.0).contains(&x) && (21.0..31.0).contains(&y);
    let in_shackle = (20.0..29.0).contains(&x) && (14.0..21.0).contains(&y);
    let hollow = (22.0..27.0).contains(&x) && (16.0..21.0).contains(&y);
    body || (in_shackle && !hollow)
}

/// Paint a one-unit ring of `halo` around `shape`, then fill it with
/// `colour`.
fn stamp(img: &mut RgbaImage, shape: &dyn Fn(f32, f32) -> bool, colour: Rgba<u8>, halo: Rgba<u8>) {
    let scale = img.width() as f32 / 32.0;
    let near = |x: f32, y: f32| {
        [-1.0f32, 0.0, 1.0].iter().any(|dx| {
            [-1.0f32, 0.0, 1.0]
                .iter()
                .any(|dy| shape(x + dx * scale, y + dy * scale))
        })
    };
    paint(img, &near, halo);
    paint(img, shape, colour);
}

/// Paint `shape` in `colour`, anti-aliased: each pixel is weighted by how
/// much of it the shape covers (4 × 4 samples), so the dot is round at
/// 16 px. `CLEAR` erases instead of painting.
fn paint(img: &mut RgbaImage, shape: &dyn Fn(f32, f32) -> bool, colour: Rgba<u8>) {
    const N: u32 = 4;
    let (w, h) = img.dimensions();
    for y in 0..h {
        for x in 0..w {
            let inside = (0..N * N)
                .filter(|i| {
                    let sx = x as f32 + (i % N) as f32 / N as f32 + 0.5 / N as f32;
                    let sy = y as f32 + (i / N) as f32 / N as f32 + 0.5 / N as f32;
                    shape(sx, sy)
                })
                .count();
            if inside == 0 {
                continue;
            }
            let cover = inside as f32 / (N * N) as f32;
            let old = *img.get_pixel(x, y);
            img.put_pixel(x, y, blend(old, colour, cover));
        }
    }
}

/// `colour` over `old` at `cover`; `CLEAR` takes `cover` of `old` away.
fn blend(old: Rgba<u8>, colour: Rgba<u8>, cover: f32) -> Rgba<u8> {
    if cover >= 1.0 {
        return colour;
    }
    let old_a = old.0[3] as f32 / 255.0;
    if colour == CLEAR {
        let mut out = old;
        out.0[3] = (old_a * (1.0 - cover) * 255.0).round() as u8;
        return out;
    }
    let src_a = cover * colour.0[3] as f32 / 255.0;
    let out_a = src_a + old_a * (1.0 - src_a);
    let channel = |c: usize| {
        let v = (colour.0[c] as f32 * src_a + old.0[c] as f32 * old_a * (1.0 - src_a)) / out_a;
        v.round() as u8
    };
    Rgba([
        channel(0),
        channel(1),
        channel(2),
        (out_a * 255.0).round() as u8,
    ])
}

/// The last state shown, so a tick that finds nothing new does nothing.
static SHOWN: Mutex<Option<TrayState>> = Mutex::new(None);

/// Show the state again now (a style or language change), even if it is
/// the one already shown.
pub fn invalidate() {
    *SHOWN.lock() = None;
}

/// Recompute the state every second and hand a change to `apply`.
pub fn spawn_watcher(app: &AppHandle, apply: fn(&AppHandle, TrayState)) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let now = current(&app);
            let changed = {
                let mut shown = SHOWN.lock();
                let changed = *shown != Some(now);
                *shown = Some(now);
                changed
            };
            if changed {
                apply(&app, now);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const INK: Rgba<u8> = Rgba([30, 41, 59, 255]);

    fn logo() -> RgbaImage {
        RgbaImage::from_pixel(32, 32, Rgba([10, 120, 110, 255]))
    }

    #[test]
    fn an_open_vault_leaves_the_icon_alone() {
        let mut img = logo();
        decorate(&mut img, TrayState::Unlocked, INK, CLEAR);
        decorate(&mut img, TrayState::NoAccount, INK, CLEAR);
        decorate(&mut img, TrayState::PhoneOnly { agent: false }, INK, CLEAR);
        assert_eq!(img, logo());
    }

    #[test]
    fn a_locked_vault_gets_a_padlock_bottom_right_and_nothing_else() {
        let mut img = logo();
        decorate(&mut img, TrayState::Locked { agent: false }, INK, CLEAR);
        assert_eq!(*img.get_pixel(20, 28), INK, "body");
        assert_eq!(*img.get_pixel(20, 16), INK, "shackle");
        assert_eq!(
            *img.get_pixel(24, 18),
            *logo().get_pixel(24, 18),
            "inside the shackle"
        );
        assert_eq!(*img.get_pixel(24, 25), CLEAR, "keyhole");
        assert_eq!(*img.get_pixel(17, 25), CLEAR, "the ring around it");
        assert_eq!(
            *img.get_pixel(5, 5),
            *logo().get_pixel(5, 5),
            "the logo elsewhere"
        );
        assert!(img.pixels().all(|p| *p != GREEN));
    }

    #[test]
    fn a_light_halo_rings_the_marks_of_the_colour_logo() {
        let white = Rgba([255; 4]);
        let mut img = logo();
        decorate(&mut img, TrayState::Locked { agent: true }, INK, white);
        assert_eq!(*img.get_pixel(17, 25), white, "ring");
        assert_eq!(*img.get_pixel(24, 25), white, "keyhole");
        assert_eq!(*img.get_pixel(20, 28), INK);
        assert_eq!(*img.get_pixel(26, 6), GREEN);
    }

    #[test]
    fn the_phone_agent_adds_a_green_dot() {
        let mut img = logo();
        decorate(&mut img, TrayState::Locked { agent: true }, INK, CLEAR);
        assert_eq!(*img.get_pixel(26, 6), GREEN);
        assert_eq!(*img.get_pixel(20, 28), INK);

        let mut img = logo();
        decorate(&mut img, TrayState::PhoneOnly { agent: true }, INK, CLEAR);
        assert_eq!(*img.get_pixel(26, 6), GREEN);
        assert_ne!(*img.get_pixel(20, 28), INK, "no vault, no padlock");
    }

    #[test]
    fn the_marks_scale_with_the_icon() {
        let mut img = RgbaImage::from_pixel(64, 64, Rgba([10, 120, 110, 255]));
        decorate(&mut img, TrayState::Locked { agent: true }, INK, CLEAR);
        assert_eq!(*img.get_pixel(40, 56), INK);
        assert_eq!(*img.get_pixel(52, 12), GREEN);
    }

    #[test]
    fn the_menu_follows_the_state() {
        let locked = TrayState::Locked { agent: false };
        assert!(!locked.can_lock());
        assert_eq!(open_label(locked, "fr"), "Déverrouiller…");
        assert_eq!(
            status_label(locked, "fr"),
            Some("Verrouillé · agent SSH arrêté")
        );
        assert_eq!(
            status_label(TrayState::Locked { agent: true }, "en"),
            Some("Locked · the phone signs")
        );

        assert!(TrayState::Unlocked.can_lock());
        assert_eq!(open_label(TrayState::Unlocked, "en"), "Open Clavix");

        let phone = TrayState::PhoneOnly { agent: true };
        assert!(!phone.can_lock());
        assert_eq!(open_label(phone, "fr"), "Ouvrir Clavix");
        assert_eq!(status_label(TrayState::NoAccount, "fr"), None);
    }

    /// `CLAVIX_TRAY_PREVIEW=<dir> cargo test tray_preview -- --ignored`
    /// writes every state in every style there, to look at.
    #[test]
    #[ignore]
    fn tray_preview() {
        let dir = std::path::PathBuf::from(std::env::var("CLAVIX_TRAY_PREVIEW").unwrap());
        std::fs::create_dir_all(&dir).unwrap();
        for (name, state) in [
            ("unlocked", TrayState::Unlocked),
            ("locked", TrayState::Locked { agent: false }),
            ("locked-phone", TrayState::Locked { agent: true }),
            ("phone-only", TrayState::PhoneOnly { agent: true }),
        ] {
            for (style, bytes, ink) in [
                ("color", &include_bytes!("../icons/32x32.png")[..], INK),
                (
                    "black",
                    &include_bytes!("../icons/tray-monochrome.png")[..],
                    Rgba([0, 0, 0, 255]),
                ),
                (
                    "white",
                    &include_bytes!("../icons/tray-monochrome.png")[..],
                    Rgba([255, 255, 255, 255]),
                ),
            ] {
                let mut img = image::load_from_memory(bytes).unwrap().to_rgba8();
                if style == "white" {
                    img.pixels_mut().for_each(|p| p.0[..3].fill(255));
                }
                let halo = if style == "color" {
                    Rgba([255; 4])
                } else {
                    CLEAR
                };
                decorate(&mut img, state, ink, halo);
                img.save(dir.join(format!("{style}-{name}.png"))).unwrap();
            }
        }
    }
}
