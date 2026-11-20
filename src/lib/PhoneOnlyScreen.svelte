<script lang="ts">
  // The whole screen of a setup with no vault: Clavix as the SSH agent of
  // a phone paired with Clavix Approve. No account, no master password.
  // The pairing block is the one of the SSH preferences, in its
  // phone-only form; this adds what a vault user finds elsewhere in the
  // preferences (where the agent listens, starting at login) and the way
  // to a vault.
  import { onDestroy } from "svelte";
  import * as m from "#lib/paraglide/messages.js";
  import { api } from "./api";
  import { formatError } from "./format";
  import PhoneSignSettings from "./PhoneSignSettings.svelte";
  import type { PhoneSignStatus } from "./types";

  let { onAddVault }: { onAddVault: () => void } = $props();

  let status = $state<PhoneSignStatus | null>(null);
  let copied = $state<string | null>(null);
  let error = $state<string | null>(null);
  let autostart = $state<boolean | null>(null);

  const socket = $derived(status?.socketPath ?? null);
  const exportLine = $derived(socket ? `export SSH_AUTH_SOCK="${socket}"` : "");
  const configLines = $derived(socket ? `Host *\n  IdentityAgent "${socket}"` : "");

  // The agent starts in the background once a phone is paired: its
  // socket is not in the status the pairing returned. Ask again a few
  // times, then leave it to the next status the block reads.
  let poll: ReturnType<typeof setTimeout> | null = null;
  let polls = 0;
  function onStatus(next: PhoneSignStatus) {
    status = next;
    if (poll) clearTimeout(poll);
    poll = null;
    if (!next.paired) {
      polls = 0;
      return;
    }
    if (next.socketPath || polls >= 20) return;
    polls += 1;
    poll = setTimeout(async () => {
      try {
        onStatus(await api.phoneSignStatus());
      } catch {
        // The block shows what is wrong with the pairing.
      }
    }, 500);
  }
  onDestroy(() => {
    if (poll) clearTimeout(poll);
  });

  $effect(() => {
    api
      .autostartEnabled()
      .then((v) => (autostart = v))
      .catch(() => (autostart = null));
  });

  async function copy(text: string) {
    try {
      await api.clipboardWrite(text);
      copied = text;
    } catch (e) {
      error = formatError(e);
    }
  }

  async function toggleAutostart(enabled: boolean) {
    error = null;
    try {
      await api.setAutostart(enabled);
      autostart = enabled;
    } catch (e) {
      error = formatError(e);
    }
  }
</script>

<section class="box phone-only">
  <PhoneSignSettings phoneOnly {onStatus} />

  {#if status?.paired}
    <section class="phone-only-ssh" aria-labelledby="phone-only-ssh-title">
      <h3 id="phone-only-ssh-title">{m.phone_only_ssh_title()}</h3>
      {#if socket}
        <p class="hint">{m.phone_only_ssh_intro()}</p>
        <p class="hint">{m.phone_only_ssh_env()}</p>
        <div class="phone-only-snippet">
          <code class="phone-only-export">{exportLine}</code>
          <button type="button" class="secondary" onclick={() => copy(exportLine)}>
            {copied === exportLine ? m.phone_only_copied() : m.phone_only_copy()}
          </button>
        </div>
        <p class="hint">{m.phone_only_ssh_config()}</p>
        <div class="phone-only-snippet">
          <code class="phone-only-config">{configLines}</code>
          <button type="button" class="secondary" onclick={() => copy(configLines)}>
            {copied === configLines ? m.phone_only_copied() : m.phone_only_copy()}
          </button>
        </div>
      {:else}
        <p class="hint phone-only-starting">{m.phone_only_ssh_starting()}</p>
      {/if}
    </section>
  {/if}

  {#if autostart !== null}
    <label class="phone-only-autostart">
      <input
        type="checkbox"
        checked={autostart}
        onchange={(e) => toggleAutostart((e.currentTarget as HTMLInputElement).checked)}
      />
      {m.phone_only_autostart()}
    </label>
  {/if}

  {#if error}
    <p class="phone-only-error" role="alert">{error}</p>
  {/if}

  <p class="phone-only-vault">
    <button type="button" class="phone-only-link" onclick={onAddVault}>
      {m.phone_only_add_vault()}
    </button>
  </p>
</section>

<style>
  .box {
    margin-top: 1.5rem;
    padding: 1rem 1.25rem;
    border-radius: 10px;
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-card);
    text-align: left;
  }

  h3 {
    margin: 1.25rem 0 0.4rem;
    font-size: 0.95rem;
  }

  .hint {
    margin: 0.35rem 0;
    font-size: 0.85rem;
    color: var(--text-secondary);
  }

  .phone-only-snippet {
    display: flex;
    gap: 0.5rem;
    align-items: flex-start;
    margin-bottom: 0.6rem;
  }

  .phone-only-snippet code {
    flex: 1;
    padding: 0.4rem 0.55rem;
    border-radius: 6px;
    background: var(--surface-sunken, var(--bg));
    font-size: 0.8rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    user-select: all;
  }

  /* base.css stacks every label vertically; a checkbox wants its text
     beside it. */
  .phone-only-autostart {
    display: flex;
    flex-direction: row;
    gap: 0.5rem;
    align-items: baseline;
    margin-top: 1rem;
    font-size: 0.9rem;
  }

  .phone-only-autostart input {
    flex: none;
    width: auto;
    margin: 0;
    padding: 0;
  }

  .phone-only-error {
    margin: 0.75rem 0 0;
    color: var(--danger-text, var(--text));
    font-size: 0.9rem;
  }

  .phone-only-vault {
    margin: 1.25rem 0 0;
    text-align: center;
    font-size: 0.85rem;
  }

  .phone-only-link {
    background: none;
    border: none;
    padding: 0;
    font: inherit;
    color: var(--link);
    text-decoration: underline;
    cursor: pointer;
  }

  .phone-only-link:hover {
    color: var(--link-hover);
  }
</style>
