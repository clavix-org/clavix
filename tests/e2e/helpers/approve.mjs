// The Clavix Approve side of a phone test: the reference relay and the
// stand-in phone, both from the clavix-approve repository at the very
// revision Clavix pins (`clavix-approve-core` in src-tauri/Cargo.toml).
// Nothing here talks to a hosted relay or to a real phone.
//
// The stand-in phone runs the modules of the approval page and signs with
// a throwaway key without asking anyone: a test tool, as its own header
// says.

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import net from "node:net";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const projectRoot = resolve(here, "../../..");
const REPOSITORY = "https://github.com/clavix-org/clavix-approve";

/** The pinned revision, as written in Cargo.toml. */
function pinnedRevision() {
  const manifest = readFileSync(resolve(projectRoot, "src-tauri/Cargo.toml"), "utf8");
  const rev = manifest.match(/clavix-approve-core\s*=\s*\{[^}]*rev\s*=\s*"([0-9a-f]+)"/)?.[1];
  if (!rev) throw new Error("no pinned clavix-approve-core revision in src-tauri/Cargo.toml");
  return rev;
}

/**
 * A checkout of clavix-approve at the pinned revision. Building Clavix
 * already fetched one into cargo's git cache; without it (a cache that
 * keeps only the bare repository), the revision is cloned once next to
 * the tests.
 */
export function approveCheckout() {
  const rev = pinnedRevision();
  const usable = (dir) => existsSync(join(dir, "relay/relay.py")) && existsSync(join(dir, "tools/fake-phone.mjs"));

  const cargoCheckouts = join(process.env.CARGO_HOME ?? join(homedir(), ".cargo"), "git/checkouts");
  if (existsSync(cargoCheckouts)) {
    for (const repo of readdirSync(cargoCheckouts).filter((n) => n.startsWith("clavix-approve-"))) {
      for (const checkout of readdirSync(join(cargoCheckouts, repo))) {
        const dir = join(cargoCheckouts, repo, checkout);
        if (rev.startsWith(checkout) || checkout.startsWith(rev)) {
          if (usable(dir)) return dir;
        }
      }
    }
  }

  const dir = resolve(here, "../.approve", rev);
  if (usable(dir)) return dir;
  mkdirSync(dir, { recursive: true });
  const git = (...args) => {
    const r = spawnSync("git", ["-C", dir, ...args], { stdio: "inherit" });
    if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed in ${dir}`);
  };
  git("init", "--quiet");
  git("fetch", "--quiet", REPOSITORY);
  git("checkout", "--quiet", rev);
  if (!usable(dir)) throw new Error(`clavix-approve ${rev} has no relay or stand-in phone`);
  return dir;
}

async function until(what, check, ms = 15_000) {
  const end = Date.now() + ms;
  for (;;) {
    if (await check()) return;
    if (Date.now() > end) throw new Error(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

/**
 * Start the reference relay on 127.0.0.1:`port`, open enrolment, no push.
 * Returns its base URL and a `stop()`.
 */
export async function startRelay(port) {
  const checkout = approveCheckout();
  const stateDir = mkdtempSync(join(tmpdir(), "clavix-e2e-relay-"));
  const child = spawn("python3", [join(checkout, "relay/relay.py")], {
    env: { ...process.env, RELAY_STATE_DIR: stateDir, RELAY_PORT: String(port), RELAY_PUSH: "off" },
    stdio: ["ignore", "inherit", "inherit"],
  });
  let exited = null;
  child.on("exit", (code) => (exited = code));
  const url = `http://127.0.0.1:${port}`;
  await until(`relay on ${url}`, async () => {
    if (exited !== null) throw new Error(`the relay exited with status ${exited} (python3-cryptography missing?)`);
    try {
      await fetch(url);
      return true;
    } catch {
      return false;
    }
  });
  return { url, stop: () => child.kill() };
}

/** A stand-in phone keeping its keys in a throwaway file. */
export function fakePhone() {
  const checkout = approveCheckout();
  const tool = join(checkout, "tools/fake-phone.mjs");
  const state = join(mkdtempSync(join(tmpdir(), "clavix-e2e-phone-")), "phone.json");
  return {
    /** Enter the pairing code; resolves once the desktop confirmed the digits. */
    pair(relay, code) {
      return new Promise((ok, ko) => {
        const p = spawn("node", [tool, "pair", "--relay", relay, "--state", state, "--code", code], {
          stdio: ["ignore", "pipe", "pipe"],
        });
        let err = "";
        p.stderr.on("data", (d) => (err += d));
        p.on("close", (status) => (status === 0 ? ok() : ko(new Error(`stand-in phone, pairing: ${err}`))));
      });
    },
    /** Approve the next request, then leave. Returns a `stop()`. */
    approveNext() {
      const p = spawn("node", [tool, "run", "--state", state, "--once"], { stdio: "ignore" });
      return () => p.kill();
    },
  };
}

const sshString = (bytes) => {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, Buffer.from(bytes)]);
};

/** A made-up server: pass the same one twice for two logins to one host. */
export function newHost() {
  return crypto.generateKeyPairSync("ed25519");
}

const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENTC_EXTENSION = 27;
export const SSH_AGENT_FAILURE = 5;
export const SSH_AGENT_SIGN_RESPONSE = 14;

/**
 * What `ssh` does at a login with a recent OpenSSH: bind the agent
 * connection to the session (host key, session id, the host's signature
 * over it), then ask for a signature of the user-auth request with the
 * key `publicKeyLine`. The host is made up; its signature is real.
 * Resolves with the type byte of the agent's answer.
 */
export async function agentLoginSignature(socketPath, publicKeyLine, host = newHost()) {
  const keyBlob = Buffer.from(publicKeyLine.trim().split(/\s+/)[1], "base64");
  const keyType = publicKeyLine.trim().split(/\s+/)[0];
  const hostRaw = Buffer.from(host.publicKey.export({ format: "jwk" }).x, "base64url");
  const hostBlob = Buffer.concat([sshString("ssh-ed25519"), sshString(hostRaw)]);
  const sessionId = crypto.randomBytes(32);
  const hostSignature = Buffer.concat([
    sshString("ssh-ed25519"),
    sshString(crypto.sign(null, sessionId, host.privateKey)),
  ]);
  const bind = Buffer.concat([
    Buffer.from([SSH_AGENTC_EXTENSION]),
    sshString("session-bind@openssh.com"),
    sshString(hostBlob),
    sshString(sessionId),
    sshString(hostSignature),
    Buffer.from([0]), // not a forwarding
  ]);
  const userauth = Buffer.concat([
    sshString(sessionId),
    Buffer.from([50]), // SSH_MSG_USERAUTH_REQUEST
    sshString("e2e"),
    sshString("ssh-connection"),
    sshString("publickey-hostbound-v00@openssh.com"),
    Buffer.from([1]),
    sshString(keyType),
    sshString(keyBlob),
    sshString(hostBlob),
  ]);
  const sign = Buffer.concat([
    Buffer.from([SSH_AGENTC_SIGN_REQUEST]),
    sshString(keyBlob),
    sshString(userauth),
    Buffer.from([0, 0, 0, 0]),
  ]);

  const socket = net.connect(socketPath);
  await new Promise((ok, ko) => socket.once("connect", ok).once("error", ko));
  try {
    let buffer = Buffer.alloc(0);
    const waiting = [];
    const deliver = () => {
      while (waiting.length && buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32BE(0)) {
        const length = buffer.readUInt32BE(0);
        waiting.shift()(buffer.subarray(4, 4 + length));
        buffer = buffer.subarray(4 + length);
      }
    };
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      deliver();
    });
    const answer = () => new Promise((ok) => (waiting.push(ok), deliver()));

    socket.write(sshString(bind));
    await answer();
    socket.write(sshString(sign));
    return (await answer())[0];
  } finally {
    socket.destroy();
  }
}
