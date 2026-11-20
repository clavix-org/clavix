// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

const apiMock = vi.hoisted(() => ({
  phoneSignStatus: vi.fn(),
  phoneSignPairCancel: vi.fn().mockResolvedValue(undefined),
  autostartEnabled: vi.fn().mockResolvedValue(true),
  setAutostart: vi.fn().mockResolvedValue(undefined),
  clipboardWrite: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("./api", () => ({ api: apiMock }));

import PhoneOnlyScreen from "./PhoneOnlyScreen.svelte";

const SOCKET = "/run/user/1000/clavix/agent.sock";
const UNPAIRED = {
  available: true,
  paired: false,
  outdated: false,
  devices: [],
  relay: null,
  label: null,
  useWhenLocked: false,
  lockedAgentRunning: false,
  socketPath: null,
  relayRefusal: null,
};
const PAIRED = {
  ...UNPAIRED,
  paired: true,
  devices: [{ id: "cd", name: "iphone", publicKey: "ecdsa-sha2-nistp256 AAAA iphone", fingerprint: "SHA256:abc" }],
  relay: "https://approve.clavix.org",
  label: "desk",
  lockedAgentRunning: true,
  socketPath: SOCKET,
};

async function flush() {
  for (let i = 0; i < 6; i++) await tick();
  await new Promise((r) => setTimeout(r, 0));
}

beforeEach(() => {
  for (const f of Object.values(apiMock)) f.mockClear();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("PhoneOnlyScreen", () => {
  it("starts with the pairing form and a way to a vault, and no ssh instructions yet", async () => {
    apiMock.phoneSignStatus.mockResolvedValue(UNPAIRED);
    const onAddVault = vi.fn();
    render(PhoneOnlyScreen, { props: { onAddVault } });
    await flush();
    expect(document.querySelector(".phone-sign-form")).not.toBeNull();
    expect(document.querySelector(".phone-only-ssh")).toBeNull();
    await fireEvent.click(document.querySelector(".phone-only-link") as HTMLButtonElement);
    expect(onAddVault).toHaveBeenCalled();
  });

  it("shows how to point ssh at the agent, with both snippets to copy", async () => {
    apiMock.phoneSignStatus.mockResolvedValue(PAIRED);
    render(PhoneOnlyScreen, { props: { onAddVault: vi.fn() } });
    await flush();
    const exportLine = `export SSH_AUTH_SOCK="${SOCKET}"`;
    expect(document.querySelector(".phone-only-export")?.textContent).toBe(exportLine);
    expect(document.querySelector(".phone-only-config")?.textContent).toBe(`Host *\n  IdentityAgent "${SOCKET}"`);
    const copies = document.querySelectorAll<HTMLButtonElement>(".phone-only-snippet button");
    await fireEvent.click(copies[0]);
    expect(apiMock.clipboardWrite).toHaveBeenCalledWith(exportLine);
    await fireEvent.click(copies[1]);
    expect(apiMock.clipboardWrite).toHaveBeenLastCalledWith(`Host *\n  IdentityAgent "${SOCKET}"`);
  });

  it("waits for the agent that starts after the pairing, then shows its socket", async () => {
    apiMock.phoneSignStatus.mockResolvedValueOnce({ ...PAIRED, lockedAgentRunning: false, socketPath: null });
    apiMock.phoneSignStatus.mockResolvedValue(PAIRED);
    render(PhoneOnlyScreen, { props: { onAddVault: vi.fn() } });
    await flush();
    expect(document.querySelector(".phone-only-starting")).not.toBeNull();
    await new Promise((r) => setTimeout(r, 650));
    await flush();
    expect(document.querySelector(".phone-only-export")?.textContent).toContain(SOCKET);
  });

  it("reads and sets the start-at-login switch", async () => {
    apiMock.phoneSignStatus.mockResolvedValue(PAIRED);
    render(PhoneOnlyScreen, { props: { onAddVault: vi.fn() } });
    await flush();
    const box = document.querySelector<HTMLInputElement>(".phone-only-autostart input");
    expect(box?.checked).toBe(true);
    await fireEvent.click(box!);
    expect(apiMock.setAutostart).toHaveBeenCalledWith(false);
  });
});
