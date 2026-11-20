// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render } from "@testing-library/svelte";
import { tick } from "svelte";

const apiMock = vi.hoisted(() => ({
  phoneStatus: vi.fn(),
  phonePairStart: vi.fn(),
  phonePairWait: vi.fn(),
  phonePairConfirm: vi.fn(),
  phonePairCancel: vi.fn().mockResolvedValue(undefined),
  phoneForget: vi.fn(),
  setPhoneApprovalOptions: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("./api", () => ({ api: apiMock }));

import PhoneApprovalSettings from "./PhoneApprovalSettings.svelte";

const UNPAIRED = {
  available: true,
  paired: false,
  outdated: false,
  devices: [],
  relay: null,
  relayRefusal: null,
};
const PAIRED = {
  available: true,
  paired: true,
  outdated: false,
  devices: ["iPhone"],
  relay: "https://approve.clavix.org",
};

async function flush() {
  for (let i = 0; i < 6; i++) await tick();
  await new Promise((r) => setTimeout(r, 0));
}

function setup(status: unknown, enabled = false) {
  apiMock.phoneStatus.mockResolvedValue(status);
  const onApply = vi.fn();
  render(PhoneApprovalSettings, {
    options: { enabled, delayS: 0 },
    confirmPolicy: "always",
    onApply,
  });
  return onApply;
}

function button(text: RegExp) {
  return Array.from(document.querySelectorAll("button")).find((b) =>
    text.test(b.textContent ?? ""),
  ) as HTMLButtonElement;
}

beforeEach(() => {
  for (const f of Object.values(apiMock)) f.mockClear();
});
afterEach(cleanup);

describe("PhoneApprovalSettings", () => {
  it("shows nothing in a build without the relay client", async () => {
    setup({ ...UNPAIRED, available: false });
    await flush();
    expect(document.querySelector(".phone-approval")).toBeNull();
  });

  it("offers the setting only once a phone is paired", async () => {
    setup(UNPAIRED);
    await flush();
    expect(document.querySelector('input[type="checkbox"]')).toBeNull();
    cleanup();
    setup(PAIRED);
    await flush();
    expect(document.querySelector(".phone-approval-devices")?.textContent).toContain("iPhone");
    expect(document.querySelector('input[type="checkbox"]')).not.toBeNull();
  });

  it("applies the setting locally and to the backend", async () => {
    const onApply = setup(PAIRED);
    await flush();
    await fireEvent.click(document.querySelector('input[type="checkbox"]') as HTMLInputElement);
    expect(onApply).toHaveBeenCalledWith({ enabled: true, delayS: 0 });
    expect(apiMock.setPhoneApprovalOptions).toHaveBeenCalledWith({ enabled: true, delayS: 0 });
  });

  it("pairs only after the user confirms the digits", async () => {
    setup(UNPAIRED);
    await flush();
    await fireEvent.click(button(/Appairer un téléphone|Pair a phone/));
    await flush();
    const inputs = document.querySelectorAll<HTMLInputElement>(".phone-approval-form input");
    expect(inputs[0].value).toBe("https://approve.clavix.org");
    await fireEvent.input(inputs[1], { target: { value: "secret" } });
    await fireEvent.input(inputs[2], { target: { value: "desk" } });

    apiMock.phonePairStart.mockResolvedValue({
      code: "cva2-x",
      link: "clavix-approve://pair?relay=https://r#cva2-x",
      qrSvg: "<svg></svg>",
    });
    apiMock.phonePairWait.mockResolvedValue({ digits: "042 917", deviceName: "iPhone" });
    apiMock.phonePairConfirm.mockResolvedValue(PAIRED);
    await fireEvent.submit(document.querySelector(".phone-approval-form") as HTMLFormElement);
    await flush();
    expect(apiMock.phonePairStart).toHaveBeenCalledWith("https://approve.clavix.org", "secret", "desk");
    expect(document.querySelector(".phone-approval-digits")?.textContent).toBe("042 917");
    expect(apiMock.phonePairConfirm).not.toHaveBeenCalled();

    await fireEvent.click(button(/Identiques|Same digits/));
    await flush();
    expect(apiMock.phonePairConfirm).toHaveBeenCalled();
    expect(document.querySelector(".phone-approval-devices")?.textContent).toContain("iPhone");
  });

  it("cancels when the digits differ", async () => {
    setup(UNPAIRED);
    await flush();
    await fireEvent.click(button(/Appairer un téléphone|Pair a phone/));
    await flush();
    apiMock.phonePairStart.mockResolvedValue({ code: "c", link: "l", qrSvg: "<svg></svg>" });
    apiMock.phonePairWait.mockResolvedValue({ digits: "111 111", deviceName: "x" });
    // Open enrolment: the secret is optional, and left empty here.
    const inputs = document.querySelectorAll<HTMLInputElement>(".phone-approval-form input");
    expect(inputs[1].required).toBe(false);
    await fireEvent.input(inputs[2], { target: { value: "desk" } });
    await fireEvent.submit(document.querySelector(".phone-approval-form") as HTMLFormElement);
    await flush();
    expect(apiMock.phonePairStart).toHaveBeenCalledWith("https://approve.clavix.org", "", "desk");
    await fireEvent.click(button(/Différents|Different/));
    await flush();
    expect(apiMock.phonePairCancel).toHaveBeenCalled();
    expect(apiMock.phonePairConfirm).not.toHaveBeenCalled();
  });

  it("says what the hosted relay refused the last request for", async () => {
    setup({ ...PAIRED, relayRefusal: "subscription_required" });
    await flush();
    expect(document.querySelector(".phone-approval-refusal")?.textContent).toContain("Clavix Approve");
  });

  it("only offers to forget a pairing made before pairing version 2", async () => {
    setup({ ...PAIRED, outdated: true });
    await flush();
    expect(document.querySelector(".phone-approval-outdated")?.textContent).toMatch(
      /appairez de nouveau|pair the phone again/,
    );
    expect(document.querySelector("#phone-approval-delay")).toBeNull();
    expect(button(/Appairer un autre|Pair another/)).toBeUndefined();
    expect(button(/Oublier|Forget/)).toBeDefined();
  });
});
