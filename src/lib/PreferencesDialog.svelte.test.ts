// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";

// The dialog probes the agent, the Yubikey and the screen-lock on open;
// none of that exists under jsdom.
vi.mock("./api", () => ({
  api: {
    autostartEnabled: vi.fn().mockResolvedValue(false),
    setAutostart: vi.fn().mockResolvedValue(undefined),
    sshAgentStatus: vi.fn().mockResolvedValue({ running: false, socketPath: null, keys: [], skipped: [] }),
    sshAuthSock: vi.fn().mockResolvedValue(null),
    yubikeyUnlockState: vi.fn().mockResolvedValue({ enrolled: false, requiresPin: false }),
    screenLockAvailable: vi.fn().mockResolvedValue(true),
    cliAccessAvailable: vi.fn().mockResolvedValue(true),
    startSshAgent: vi.fn(),
    stopSshAgent: vi.fn(),
    enrollYubikeyUnlock: vi.fn(),
    disenrollYubikeyUnlock: vi.fn(),
    phoneStatus: vi.fn().mockResolvedValue({ available: false }),
    phoneSignStatus: vi.fn().mockResolvedValue({ available: false }),
    phonePairCancel: vi.fn().mockResolvedValue(undefined),
    phoneSignPairCancel: vi.fn().mockResolvedValue(undefined),
  },
}));

import PreferencesDialog from "./PreferencesDialog.svelte";
import { api } from "./api";

beforeEach(() => {
  vi.mocked(api.autostartEnabled).mockResolvedValue(false);
  vi.mocked(api.setAutostart).mockReset().mockResolvedValue(undefined);
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    this.open = false;
  };
});

afterEach(cleanup);

async function flush() {
  for (let i = 0; i < 4; i++) await tick();
}

function mount() {
  const onApplyTheme = vi.fn();
  const { component, container } = render(PreferencesDialog, {
    props: {
      currentLocale: "fr" as const,
      themePref: "auto" as const,
      autoLockMinutes: 10,
      autoLockTrigger: "idle" as const,
      closeToTray: true,
      minimizeToTray: false,
      hideDockOnTray: false,
      trayIconStyle: "color" as const,
      onApplyTrayIconStyle: vi.fn(),
      requireNarrowing: true,
      toolbarAlign: "left" as const,
      autoSyncMinutes: 30,
      sshAgentConfirm: "session" as const,
      sshAgentAutoStart: false,
      blurNotes: true,
      onApplyBlurNotes: vi.fn(),
      searchNotes: true,
      onApplySearchNotes: vi.fn(),
      cliAccess: false,
      onApplyCliAccess: vi.fn(),
      onApplyLocale: vi.fn(),
      onApplyTheme,
      onApplyAutoLock: vi.fn(),
      onApplyCloseToTray: vi.fn(),
      onApplyMinimizeToTray: vi.fn(),
      onApplyHideDockOnTray: vi.fn(),
      onApplyRequireNarrowing: vi.fn(),
      onApplyToolbarAlign: vi.fn(),
      onApplyAutoSyncMinutes: vi.fn(),
      onApplySshAgentConfirm: vi.fn(),
      onApplySshAgentAutoStart: vi.fn(),
      onCopySocketPath: vi.fn(),
      onCopyShellCommand: vi.fn(),
    },
  }) as unknown as { component: { open: (tab?: "ssh") => Promise<void> }; container: HTMLElement };
  const tabs = () => Array.from(container.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
  const panel = () => container.querySelector('[role="tabpanel"]') as HTMLElement;
  return { component, container, tabs, panel, onApplyTheme };
}

function key(target: Element, k: string) {
  const event = new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true });
  target.dispatchEvent(event);
  return event;
}

describe("PreferencesDialog", () => {
  it("says what once per session remembers, next to that choice only", async () => {
    const { component, container, tabs } = mount();
    await component.open();
    tabs()
      .find((t) => t.id === "prefs-tab-ssh")
      ?.click();
    await flush();
    // The fixture's policy is "session".
    const hint = container.querySelector(".ssh-confirm-session-hint")?.textContent ?? "";
    expect(hint).toMatch(/verrouillage|locked/);
    expect(hint).toMatch(/autre serveur|another server/);
  });

  it("opens on the SSH tab when asked to (a click on the relay notification)", async () => {
    const { component, tabs, panel } = mount();
    await component.open("ssh");
    await flush();
    expect(panel().id).toBe("prefs-panel-ssh");
    expect(tabs().find((t) => t.id === "prefs-tab-ssh")?.getAttribute("aria-selected")).toBe("true");
  });

  // The dialog's content stays mounted while it is closed, SSH tab
  // included: what happened meanwhile must not be hidden by a status
  // read at the first opening.
  it("reads the phone pairing again each time it is opened", async () => {
    const paired = {
      available: true,
      paired: true,
      outdated: false,
      devices: [{ id: "cd", name: "iphone", publicKey: "ecdsa-sha2-nistp256 AAAA iphone", fingerprint: "SHA256:abc" }],
      relay: "https://approve.clavix.org",
      label: "desk",
      useWhenLocked: true,
      lockedAgentRunning: false,
      relayRefusal: null,
    };
    vi.mocked(api.phoneSignStatus).mockResolvedValue(paired as never);
    const { component, container, tabs } = mount();
    await component.open();
    tabs()
      .find((t) => t.id === "prefs-tab-ssh")
      ?.click();
    await flush();
    await flush();
    expect(container.querySelector(".phone-sign-devices")).not.toBeNull();
    expect(container.querySelector(".phone-sign-refusal")).toBeNull();

    // A sign request is refused by the relay while the dialog is closed.
    container.querySelector("dialog")?.close();
    vi.mocked(api.phoneSignStatus).mockResolvedValue({ ...paired, relayRefusal: "subscription_required" } as never);
    await component.open();
    await flush();
    await flush();
    expect(container.querySelector(".phone-sign-refusal")?.textContent).toContain("Clavix Approve");
    vi.mocked(api.phoneSignStatus).mockResolvedValue({ available: false } as never);
  });

  it("reads the OS autostart setting and disables it on request", async () => {
    vi.mocked(api.autostartEnabled).mockResolvedValue(true);
    const { component, tabs, panel } = mount();
    await component.open();
    await flush();
    tabs()[2].click();
    await flush();
    const checkbox = panel().querySelector<HTMLInputElement>('input[type="checkbox"]')!;
    expect(checkbox.checked).toBe(true);
    checkbox.click();
    await flush();
    expect(api.setAutostart).toHaveBeenCalledWith(false);
    expect(checkbox.checked).toBe(false);
  });

  it("keeps autostart off and displays an error if OS registration fails", async () => {
    vi.mocked(api.setAutostart).mockRejectedValueOnce(new Error("Registration denied"));
    const { component, tabs, panel } = mount();
    await component.open();
    await flush();
    tabs()[2].click();
    await flush();
    const checkbox = panel().querySelector<HTMLInputElement>('input[type="checkbox"]')!;
    checkbox.click();
    await flush();
    expect(api.setAutostart).toHaveBeenCalledWith(true);
    expect(checkbox.checked).toBe(false);
    expect(panel().querySelector('[role="alert"]')?.textContent).toContain("Registration denied");
  });

  it("opens on the general tab with one panel and one Tab stop", async () => {
    const { component, tabs, panel } = mount();
    await component.open();
    await flush();
    expect(tabs()).toHaveLength(5);
    expect(tabs().filter((t) => t.tabIndex === 0)).toHaveLength(1);
    expect(tabs()[0].getAttribute("aria-selected")).toBe("true");
    expect(panel().id).toBe("prefs-panel-general");
    expect(panel().querySelector("select")).not.toBeNull();
  });

  it("switches panels on click", async () => {
    const { component, tabs, panel } = mount();
    await component.open();
    await flush();
    tabs()[1].click();
    await flush();
    expect(panel().id).toBe("prefs-panel-security");
    expect(panel().querySelector("optgroup")).not.toBeNull();
  });

  it("moves between tabs with the arrow keys, wrapping at the ends", async () => {
    const { component, tabs, panel } = mount();
    await component.open();
    await flush();
    tabs()[0].focus();
    key(tabs()[0], "ArrowLeft");
    await flush();
    expect(panel().id).toBe("prefs-panel-yubikey");
    expect(document.activeElement).toBe(tabs()[4]);
    key(tabs()[4], "ArrowRight");
    await flush();
    expect(panel().id).toBe("prefs-panel-general");
    key(tabs()[0], "End");
    await flush();
    expect(panel().id).toBe("prefs-panel-yubikey");
  });

  it("applies the theme from the general panel", async () => {
    const { component, panel, onApplyTheme } = mount();
    await component.open();
    await flush();
    const selects = panel().querySelectorAll("select");
    const theme = selects[1] as HTMLSelectElement;
    theme.value = "light";
    theme.dispatchEvent(new Event("change", { bubbles: true }));
    expect(onApplyTheme).toHaveBeenCalledWith("light");
  });
});
