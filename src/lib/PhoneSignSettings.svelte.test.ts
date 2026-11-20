// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render } from "@testing-library/svelte";
import { tick } from "svelte";

const apiMock = vi.hoisted(() => ({
  phoneSignStatus: vi.fn(),
  phoneSignPairStart: vi.fn(),
  phoneSignPairWait: vi.fn(),
  phoneSignPairConfirm: vi.fn(),
  phoneSignPairCancel: vi.fn().mockResolvedValue(undefined),
  phoneSignForget: vi.fn(),
  phoneSignSetUseWhenLocked: vi.fn(),
  clipboardWrite: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("./api", () => ({ api: apiMock }));

import PhoneSignSettings from "./PhoneSignSettings.svelte";

const KEY = "ecdsa-sha2-nistp256 AAAAE2VjZHNh iphone";
const UNPAIRED = {
  available: true,
  paired: false,
  outdated: false,
  devices: [],
  relay: null,
  label: null,
  useWhenLocked: false,
  lockedAgentRunning: false,
  relayRefusal: null,
};
const PAIRED = {
  ...UNPAIRED,
  paired: true,
  devices: [{ id: "cdcdcdcdcdcdcdcd", name: "iphone", publicKey: KEY, fingerprint: "SHA256:abc" }],
  relay: "https://approve.clavix.org",
  label: "desk",
  useWhenLocked: true,
};

async function flush() {
  for (let i = 0; i < 6; i++) await tick();
  await new Promise((r) => setTimeout(r, 0));
}

function setup(status: unknown, props: Record<string, unknown> = {}) {
  apiMock.phoneSignStatus.mockResolvedValue(status);
  render(PhoneSignSettings, { props });
}

function button(text: RegExp) {
  return Array.from(document.querySelectorAll(".phone-sign button")).find((b) =>
    text.test(b.textContent ?? ""),
  ) as HTMLButtonElement;
}

beforeEach(() => {
  for (const f of Object.values(apiMock)) f.mockClear();
});
afterEach(cleanup);

describe("PhoneSignSettings", () => {
  it("is the first-launch form in phone-only mode: one field to fill, the relay tucked away", async () => {
    const onStatus = vi.fn();
    setup(UNPAIRED, { phoneOnly: true, onStatus });
    await flush();
    expect(onStatus).toHaveBeenCalledWith(expect.objectContaining({ paired: false }));
    // The form is there without a click, with a name already in it.
    const form = document.querySelector(".phone-sign-form") as HTMLFormElement;
    expect(form).not.toBeNull();
    const relay = form.querySelector<HTMLInputElement>("details.phone-sign-relay input[type=url]");
    expect(relay?.value).toBe("https://approve.clavix.org");
    expect(form.querySelector("details")?.open).toBe(false);
    apiMock.phoneSignPairStart.mockResolvedValue({ code: "cva2-x", link: "clavix-approve://x", qrSvg: "<svg></svg>" });
    apiMock.phoneSignPairWait.mockReturnValue(new Promise(() => {}));
    await fireEvent.submit(form);
    await flush();
    const [usedRelay, secret, label] = apiMock.phoneSignPairStart.mock.calls[0];
    expect(usedRelay).toBe("https://approve.clavix.org");
    expect(secret).toBe("");
    expect(label.length).toBeGreaterThan(0);
  });

  it("has no locked-vault switch in phone-only mode, and says where the key goes", async () => {
    setup(PAIRED, { phoneOnly: true });
    await flush();
    expect(document.querySelector(".phone-sign-devices")?.textContent).toContain("iphone");
    expect(document.querySelector(".phone-sign-use")).toBeNull();
    expect(document.querySelector("#phone-sign-title")?.textContent).not.toMatch(/verrouillé|locked/);
  });

  it("shows nothing in a build without the relay client", async () => {
    setup({ ...UNPAIRED, available: false });
    await flush();
    expect(document.querySelector(".phone-sign")).toBeNull();
  });

  it("says why when the pairing cannot be read, instead of showing nothing", async () => {
    apiMock.phoneSignStatus.mockRejectedValue({
      code: "phone_error",
      data: { kind: "exposed", reason: "/home/u/phone-sign/state.json is accessible by other users" },
    });
    render(PhoneSignSettings);
    await flush();
    const text = document.querySelector(".phone-sign .audit-error")?.textContent ?? "";
    expect(text).toContain("chmod 600");
    expect(text).toContain("/home/u/phone-sign/state.json");
    expect(button(/./)).toBeUndefined();
  });

  it("says what the hosted relay refused the last sign request for", async () => {
    setup({ ...PAIRED, relayRefusal: "subscription_required" });
    await flush();
    expect(document.querySelector(".phone-sign-refusal")?.textContent).toContain("Clavix Approve");
    cleanup();
    setup({ ...PAIRED, relayRefusal: "machine_limit" });
    await flush();
    expect(document.querySelector(".phone-sign-refusal")?.textContent).toMatch(/machines/);
    cleanup();
    setup(PAIRED);
    await flush();
    expect(document.querySelector(".phone-sign-refusal")).toBeNull();
  });

  it("lists the signing phones with their key and the locked-vault switch", async () => {
    setup(PAIRED);
    await flush();
    const devices = document.querySelector(".phone-sign-devices")?.textContent ?? "";
    expect(devices).toContain("iphone");
    expect(devices).toContain("SHA256:abc");
    const toggle = document.querySelector<HTMLInputElement>(".phone-sign-use");
    expect(toggle?.checked).toBe(true);

    await fireEvent.click(button(/Copier la clé|Copy the key/));
    await flush();
    expect(apiMock.clipboardWrite).toHaveBeenCalledWith(KEY);
  });

  it("turns the locked-vault agent off through the backend", async () => {
    setup(PAIRED);
    await flush();
    apiMock.phoneSignSetUseWhenLocked.mockResolvedValue({ ...PAIRED, useWhenLocked: false });
    await fireEvent.click(document.querySelector(".phone-sign-use") as HTMLInputElement);
    await flush();
    expect(apiMock.phoneSignSetUseWhenLocked).toHaveBeenCalledWith(false);
    expect(document.querySelector<HTMLInputElement>(".phone-sign-use")?.checked).toBe(false);
  });

  it("pairs after the digits match, then shows the key for authorized_keys", async () => {
    setup(UNPAIRED);
    await flush();
    expect(document.querySelector(".phone-sign-use")).toBeNull();
    await fireEvent.click(button(/Appairer un téléphone signataire|Pair a phone for signing/));
    await flush();
    const inputs = document.querySelectorAll<HTMLInputElement>(".phone-sign-form input");
    expect(inputs[0].value).toBe("https://approve.clavix.org");
    await fireEvent.input(inputs[1], { target: { value: "secret" } });
    await fireEvent.input(inputs[2], { target: { value: "desk" } });

    apiMock.phoneSignPairStart.mockResolvedValue({
      code: "cva2-x",
      link: "clavix-approve://pair?relay=https://approve.clavix.org#cva2-x",
      qrSvg: "<svg></svg>",
    });
    apiMock.phoneSignPairWait.mockResolvedValue({ digits: "042 917", deviceName: "iphone" });
    apiMock.phoneSignPairConfirm.mockResolvedValue({ status: PAIRED, publicKey: KEY, renewed: false });
    await fireEvent.submit(document.querySelector(".phone-sign-form") as HTMLFormElement);
    await flush();
    expect(apiMock.phoneSignPairStart).toHaveBeenCalledWith(
      "https://approve.clavix.org",
      "secret",
      "desk",
    );
    expect(document.querySelector(".phone-approval-digits")?.textContent).toBe("042 917");
    expect(apiMock.phoneSignPairConfirm).not.toHaveBeenCalled();

    await fireEvent.click(button(/Identiques|Same digits/));
    await flush();
    expect(apiMock.phoneSignPairConfirm).toHaveBeenCalled();
    expect(document.querySelector(".phone-sign-pubkey")?.textContent).toBe(KEY);
  });

  it("shows the pasteable code while waiting, and cancels when the digits differ", async () => {
    setup(UNPAIRED);
    await flush();
    await fireEvent.click(button(/Appairer un téléphone signataire|Pair a phone for signing/));
    await flush();
    let release: (v: unknown) => void = () => {};
    apiMock.phoneSignPairStart.mockResolvedValue({
      code: "cva2-c",
      link: "clavix-approve://pair?relay=https://r#cva2-c",
      qrSvg: "<svg></svg>",
    });
    apiMock.phoneSignPairWait.mockReturnValue(new Promise((r) => (release = r)));
    // Open enrolment: the secret is optional, and left empty here.
    const inputs = document.querySelectorAll<HTMLInputElement>(".phone-sign-form input");
    expect(inputs[1].required).toBe(false);
    await fireEvent.input(inputs[2], { target: { value: "desk" } });
    await fireEvent.submit(document.querySelector(".phone-sign-form") as HTMLFormElement);
    await flush();
    expect(apiMock.phoneSignPairStart).toHaveBeenCalledWith("https://approve.clavix.org", "", "desk");
    expect(document.querySelector(".phone-approval-code")?.textContent).toBe("cva2-c");
    release({ digits: "111 111", deviceName: "x" });
    await flush();
    await fireEvent.click(button(/Différents|Different/));
    await flush();
    expect(apiMock.phoneSignPairCancel).toHaveBeenCalled();
    expect(apiMock.phoneSignPairConfirm).not.toHaveBeenCalled();
  });

  it("only offers to forget a pairing made before pairing version 2", async () => {
    setup({ ...PAIRED, outdated: true });
    await flush();
    expect(document.querySelector(".phone-sign-outdated")?.textContent).toMatch(
      /appairez de nouveau|pair the phone again/,
    );
    expect(document.querySelector(".phone-sign-use")).toBeNull();
    expect(button(/Ajouter un téléphone|Add another phone/)).toBeUndefined();
    expect(button(/^\s*(Oublier|Forget)\s*$/)).toBeDefined();
  });

  it("takes an unconfirmed phone off the relay when the dialog closes", async () => {
    setup(UNPAIRED);
    await flush();
    await fireEvent.click(button(/Appairer un téléphone signataire|Pair a phone for signing/));
    await flush();
    apiMock.phoneSignPairStart.mockResolvedValue({ code: "c", link: "l", qrSvg: "<svg></svg>" });
    apiMock.phoneSignPairWait.mockResolvedValue({ digits: "111 111", deviceName: "x" });
    await fireEvent.submit(document.querySelector(".phone-sign-form") as HTMLFormElement);
    await flush();
    expect(apiMock.phoneSignPairCancel).not.toHaveBeenCalled();
    cleanup();
    expect(apiMock.phoneSignPairCancel).toHaveBeenCalled();
  });

  it("adds one more phone to an existing pairing", async () => {
    setup(PAIRED);
    await flush();
    apiMock.phoneSignPairStart.mockResolvedValue({ code: "c", link: "l", qrSvg: "<svg></svg>" });
    apiMock.phoneSignPairWait.mockReturnValue(new Promise(() => {}));
    await fireEvent.click(button(/Ajouter un téléphone|Add another phone/));
    await flush();
    expect(apiMock.phoneSignPairStart).toHaveBeenCalled();
    expect(document.querySelector(".phone-approval-qr")).not.toBeNull();
  });

  it("forgets a phone on the relay, and here only if the relay fails", async () => {
    setup(PAIRED);
    await flush();
    apiMock.phoneSignForget.mockRejectedValueOnce(new Error("relay down"));
    await fireEvent.click(button(/^\s*(Oublier|Forget)\s*$/));
    await flush();
    expect(apiMock.phoneSignForget).toHaveBeenCalledWith("cdcdcdcdcdcdcdcd", false);
    // The escape hatch comes with what it leaves behind.
    expect(document.body.textContent).toMatch(/reste appairé sur le relais|stays paired on the relay/);
    apiMock.phoneSignForget.mockResolvedValueOnce(UNPAIRED);
    await fireEvent.click(button(/Oublier ici quand même|Forget here anyway/));
    await flush();
    expect(apiMock.phoneSignForget).toHaveBeenLastCalledWith("cdcdcdcdcdcdcdcd", true);
    expect(document.querySelector(".phone-sign-devices")).toBeNull();
  });
});
