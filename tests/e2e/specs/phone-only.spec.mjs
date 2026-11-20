// Phone-only mode, end to end: Clavix with no vault at all, as the SSH
// agent of a phone paired with Clavix Approve.
//
// No Vaultwarden here. The other end is the reference relay and the
// stand-in phone of the clavix-approve repository, at the revision Clavix
// pins (helpers/approve.mjs); `ssh` is played by a client that speaks the
// agent protocol the way OpenSSH does at a login.
//
// What must hold:
//   - a fresh profile can choose "phone only", pair, and sign, without a
//     server address, an account or a master password;
//   - after a restart the agent is back by itself, with no unlock screen:
//     the keys are on the phone, there is nothing to unlock.

import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { sandboxHome } from "../wdio.conf.mjs";
import {
  SSH_AGENT_SIGN_RESPONSE,
  agentLoginSignature,
  fakePhone,
  startRelay,
} from "../helpers/approve.mjs";

const RELAY_PORT = 18765;

const exists = (selector) => browser.execute((s) => !!document.querySelector(s), selector);
const text = (selector) => browser.execute((s) => document.querySelector(s)?.textContent ?? "", selector);
const click = (selector) => browser.execute((s) => document.querySelector(s)?.click(), selector);

async function shown(selector, what, timeout = 20_000) {
  await browser.waitUntil(() => exists(selector), { timeout, timeoutMsg: `${what} never appeared` });
}

/** The socket the screen tells the user to point ssh at. */
async function advertisedSocket() {
  await shown(".phone-only-export", "the SSH_AUTH_SOCK line");
  const line = await text(".phone-only-export");
  const socket = line.match(/^export SSH_AUTH_SOCK="(.+)"$/)?.[1];
  if (!socket) throw new Error(`unexpected SSH_AUTH_SOCK line: ${line}`);
  return socket;
}

describe("Phone-only mode", () => {
  let relay;
  const phone = fakePhone();
  let publicKey;

  before(async () => {
    relay = await startRelay(RELAY_PORT);
  });
  after(() => relay?.stop());

  async function signsALogin() {
    const stop = phone.approveNext();
    try {
      // The stand-in phone polls the relay; give it a moment to be there.
      await browser.pause(800);
      return await agentLoginSignature(await advertisedSocket(), publicKey);
    } finally {
      stop();
    }
  }

  it("pairs a phone and signs a login with no vault at all", async () => {
    await shown(".onboarding .choice-phone", "the first-launch choice");
    await click(".onboarding .choice-phone");
    await shown(".phone-only .phone-sign-form", "the pairing form");

    // The relay defaults to the hosted one; this test has its own.
    await browser.execute((url) => {
      const input = document.querySelector("details.phone-sign-relay input[type=url]");
      input.value = url;
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }, relay.url);
    await click(".phone-sign-form button[type=submit]");

    await shown(".phone-approval-qr svg", "the pairing QR code");
    const code = (await text(".phone-approval-code")).trim();
    expect(code).toMatch(/^cva2-/);
    const paired = phone.pair(relay.url, code);

    // Both sides show the same digits; the user says so here.
    await shown(".phone-approval-digits", "the digits to compare");
    await browser.execute(() => {
      const actions = document.querySelectorAll(".phone-approval-pairing .phone-approval-actions button");
      actions[actions.length - 1].click();
    });
    await paired;

    await shown(".phone-sign-pubkey", "the phone's public key");
    publicKey = (await text(".phone-sign-pubkey")).trim();
    expect(publicKey).toMatch(/^(ecdsa-sha2-nistp256|ssh-ed25519) /);

    // The agent starts by itself once a phone is paired, and the screen
    // then says where it listens, both ways.
    const socket = await advertisedSocket();
    expect(await text(".phone-only-config")).toBe(`Host *\n  IdentityAgent "${socket}"`);

    expect(await signsALogin()).toBe(SSH_AGENT_SIGN_RESPONSE);
  });

  it("turned on start at login, inside the test's own home directory", async () => {
    // ssh fails while Clavix is not running, so the mode starts it at
    // login. The entry must be the sandbox's: the suite runs on developer
    // machines too, and theirs is not ours to rewrite.
    const autostart = join(sandboxHome, ".config/autostart");
    await browser.waitUntil(() => existsSync(autostart) && readdirSync(autostart).length > 0, {
      timeout: 10_000,
      timeoutMsg: `no autostart entry in ${autostart}`,
    });
    expect(await exists(".phone-only-autostart input:checked")).toBe(true);
  });

  it("is back after a restart, with nothing to unlock", async () => {
    // A new WebDriver session is a new Clavix process on the same profile.
    await browser.reloadSession();

    await shown(".phone-only", "the phone-only screen");
    expect(await exists('input[type="password"]')).toBe(false);
    expect(await exists(".onboarding")).toBe(false);
    expect(await text(".phone-sign-devices")).toContain("fake-phone");

    expect(await signsALogin()).toBe(SSH_AGENT_SIGN_RESPONSE);
  });
});
