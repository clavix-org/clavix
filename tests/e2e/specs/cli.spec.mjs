// The `clavix item …` command line, against the real app.
//
// The command line is the same binary started a second time: it holds no
// key, connects to the socket of the running instance and asks it to do
// the write. What only an end-to-end run can prove:
//
//   - the second launch finds the first one's socket (same runtime
//     directory) and does not start a window of its own;
//   - a write made from the terminal reaches Vaultwarden through the
//     commands the window uses, and the list shows it *without a sync
//     being asked for* (the `clavix:vault-changed` event);
//   - the socket only exists while the preference is on, and a locked
//     vault refuses instead of failing obscurely.
//
// Everything is created by this spec and removed through the trash, so
// the seeded fixtures the other specs rely on are left alone.

import { spawnSync } from "node:child_process";
import { loginAsSeededUser } from "../helpers/auth.mjs";
import { app, sandboxHome, sandboxRuntimeDir } from "../wdio.conf.mjs";

const NAME = "CLI spec item";
const PASSWORD = "s3cret from the terminal";

/** Run `clavix item …` in the sandbox the app under test runs in. */
function clavixItem(args, input = "") {
  const result = spawnSync(app, ["item", ...args], {
    input,
    encoding: "utf8",
    timeout: 60_000,
    env: {
      ...process.env,
      XDG_RUNTIME_DIR: sandboxRuntimeDir,
      HOME: sandboxHome,
    },
  });
  return {
    code: result.status,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim(),
  };
}

function expectOk(result, what) {
  if (result.code !== 0) {
    throw new Error(`${what}: exit ${result.code}, stderr: ${result.stderr}`);
  }
}

function expectRefused(result, pattern, what) {
  if (result.code !== 1 || !pattern.test(result.stderr)) {
    throw new Error(
      `${what}: expected exit 1 matching ${pattern}, got exit ${result.code}, stderr: ${result.stderr}`,
    );
  }
}

function invoke(command, args) {
  return browser.execute(
    async (command, args) => {
      // @ts-expect-error — tauri injects this global
      return await window.__TAURI__.core.invoke(command, args);
    },
    command,
    args ?? {},
  );
}

/** What the *window* currently lists for `name`, without asking for a sync. */
async function waitForRow(name, { present }) {
  await browser.waitUntil(
    async () => {
      const listed = await browser.execute(
        (name) =>
          Array.from(document.querySelectorAll(".cipher-row")).some((row) =>
            (row.textContent ?? "").includes(name),
          ),
        name,
      );
      return listed === present;
    },
    {
      timeout: 30_000,
      timeoutMsg: `the list never ${present ? "showed" : "dropped"} ${JSON.stringify(name)} on its own`,
    },
  );
}

describe("Command line (clavix item)", () => {
  it("changes the open vault from a terminal, and the window follows", async () => {
    await loginAsSeededUser();

    // Off by default: no socket, and the message says where to turn it on.
    expectRefused(
      clavixItem(["delete", "GitHub"]),
      /command-line access is turned off/,
      "with the preference off",
    );

    // Turn it on where a user would: Preferences > Security.
    const prefsButton = await $('button[aria-label="Préférences"]');
    await prefsButton.click();
    const securityTab = await $("#prefs-tab-security");
    await securityTab.click();
    const toggle = await $(
      "//label[contains(., 'ligne de commande')]/input[@type='checkbox']",
    );
    await toggle.waitForDisplayed({ timeout: 10_000 });
    await toggle.click();
    await browser.waitUntil(
      async () =>
        (await browser.execute(() => localStorage.getItem("clavix.cliAccess"))) === "true",
      { timeoutMsg: "the preference was never stored" },
    );
    await browser.keys("Escape");

    // The command line's own mistakes never reach the app.
    const usage = clavixItem(["create", "--name", NAME, "--password", "nope"]);
    if (usage.code !== 2 || !/--password-stdin/.test(usage.stderr)) {
      throw new Error(`a password argument must be refused: ${JSON.stringify(usage)}`);
    }

    // Create. The id comes back on stdout; the row appears by itself.
    const created = clavixItem(
      [
        "create",
        "--name",
        NAME,
        "--username",
        "cli-user",
        "--uri",
        "https://cli.example",
        "--notes",
        "made in a terminal",
        "--password-stdin",
      ],
      `${PASSWORD}\n`,
    );
    expectOk(created, "create");
    const id = created.stdout;
    if (!/^[0-9a-f-]{36}$/.test(id)) {
      throw new Error(`create should print the new item's id, got: ${created.stdout}`);
    }
    await waitForRow(NAME, { present: true });

    const password = await invoke("reveal_field", { id, field: "password" });
    if (password !== PASSWORD) {
      throw new Error("the password stored is not the one piped in");
    }

    // Edit by name: only what is named changes.
    expectOk(
      clavixItem(["edit", NAME, "--username", "renamed-user", "--favorite"]),
      "edit",
    );
    const detail = await invoke("get_cipher", { id });
    if (detail.login?.username !== "renamed-user") {
      throw new Error(`username not updated: ${JSON.stringify(detail.login?.username)}`);
    }
    if (detail.notes !== "made in a terminal" || detail.login?.uris?.[0] !== "https://cli.example") {
      throw new Error("an edit dropped fields it did not name");
    }
    if ((await invoke("reveal_field", { id, field: "password" })) !== PASSWORD) {
      throw new Error("an edit that did not name the password changed it");
    }
    // The server agrees, not just the Rust copy.
    const synced = await invoke("sync");
    const row = synced.ciphers.find((c) => c.id === id);
    if (!row?.favorite || row.username !== "renamed-user") {
      throw new Error(`the server copy does not carry the edit: ${JSON.stringify(row)}`);
    }

    // What it will not do.
    expectRefused(
      clavixItem(["edit", NAME, "--folder", "no such folder"]),
      /no folder "no such folder"/,
      "an unknown folder",
    );
    expectRefused(clavixItem(["delete", "no such item"]), /no item "no such item"/, "an unknown item");
    const guardedId = await invoke("create_cipher", {
      input: { name: "CLI spec guarded", cipherType: 1, login: {}, reprompt: true },
    });
    expectRefused(
      clavixItem(["edit", guardedId, "--username", "x"]),
      /master password/,
      "an item that asks for the master password",
    );
    expectOk(clavixItem(["delete", guardedId]), "delete of the guarded item");

    // Trash and back, both visible in the list without a sync.
    expectOk(clavixItem(["delete", NAME]), "delete");
    await waitForRow(NAME, { present: false });
    expectRefused(clavixItem(["delete", id]), /in the trash/, "a second delete");
    expectOk(clavixItem(["restore", NAME]), "restore");
    await waitForRow(NAME, { present: true });
    expectOk(clavixItem(["delete", id]), "final delete");
    await waitForRow(NAME, { present: false });

    // A locked vault answers, and says what to do.
    await invoke("lock");
    expectRefused(clavixItem(["restore", id]), /vault is locked/, "with the vault locked");

    // And the preference closes the door again.
    await invoke("set_cli_access", { enabled: false });
    expectRefused(
      clavixItem(["restore", id]),
      /command-line access is turned off/,
      "after turning the preference off",
    );
  });
});
