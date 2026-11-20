<script lang="ts">
  // "Ask the phone too" for SSH-agent confirmations: the setting, and
  // pairing / forgetting the phone. Hidden entirely in builds without the
  // relay client (`phone-approval` feature).
  import { onMount } from "svelte";
  import * as m from "#lib/paraglide/messages.js";
  import { api } from "./api";
  import { formatError } from "./format";
  import PasswordInput from "./PasswordInput.svelte";
  import { DEFAULT_PHONE_RELAY } from "./phone";
  import type { SshAgentConfirm } from "./prefs.svelte";
  import type {
    PhoneApprovalOptions,
    PhonePairCandidate,
    PhonePairOffer,
    PhoneStatus,
  } from "./types";

  type Props = {
    options: PhoneApprovalOptions;
    confirmPolicy: SshAgentConfirm;
    onApply: (options: PhoneApprovalOptions) => void;
  };
  let { options, confirmPolicy, onApply }: Props = $props();

  let status = $state<PhoneStatus | null>(null);
  let busy = $state(false);
  let error = $state<string | null>(null);

  // Pairing form and flow.
  let pairing = $state(false);
  let relay = $state(DEFAULT_PHONE_RELAY);
  let enrollSecret = $state("");
  let label = $state("");
  let offer = $state<PhonePairOffer | null>(null);
  let candidate = $state<PhonePairCandidate | null>(null);

  onMount(() => {
    refresh();
    return () => {
      // Leaving the dialog mid-pairing: stop waiting on the relay, and
      // take a phone that answered but was never confirmed off it again.
      if (offer) api.phonePairCancel().catch(() => {});
    };
  });

  async function refresh() {
    try {
      status = await api.phoneStatus();
    } catch (e) {
      error = formatError(e);
    }
  }

  function apply(next: PhoneApprovalOptions) {
    onApply(next);
    api.setPhoneApprovalOptions(next).catch((e) => (error = formatError(e)));
  }

  function setDelay(raw: string) {
    const n = Math.round(Number(raw));
    apply({ ...options, delayS: Number.isFinite(n) ? Math.min(Math.max(n, 0), 60) : 0 });
  }

  async function startPairing() {
    busy = true;
    error = null;
    candidate = null;
    try {
      offer = await api.phonePairStart(relay, enrollSecret, label);
    } catch (e) {
      error = formatError(e);
      busy = false;
      return;
    }
    busy = false;
    try {
      candidate = await api.phonePairWait();
    } catch (e) {
      // Cancelled by the user, or the code expired.
      if (offer) error = formatError(e);
      offer = null;
    }
  }

  async function confirmPairing() {
    busy = true;
    error = null;
    try {
      status = await api.phonePairConfirm();
      enrollSecret = "";
      pairing = false;
    } catch (e) {
      error = formatError(e);
    } finally {
      offer = null;
      candidate = null;
      busy = false;
    }
  }

  async function cancelPairing() {
    offer = null;
    candidate = null;
    pairing = false;
    await api.phonePairCancel().catch(() => {});
  }

  async function forget() {
    busy = true;
    error = null;
    try {
      status = await api.phoneForget();
      if (options.enabled) apply({ ...options, enabled: false });
    } catch (e) {
      error = formatError(e);
    } finally {
      busy = false;
    }
  }
</script>

{#if status?.available}
  <section class="phone-approval" aria-labelledby="phone-approval-title">
    <h3 id="phone-approval-title">{m.phone_approval_title()}</h3>
    <p class="hint">{m.phone_approval_intro()}</p>

    {#if status.paired}
      <dl class="phone-approval-setting">
        <dt>{m.phone_approval_paired_label()}</dt>
        <dd>
          <ul class="phone-approval-devices">
            {#each status.devices as name, i (i)}
              <li>{name || m.phone_approval_unnamed()}</li>
            {/each}
          </ul>
          <span class="hint">{status.relay}</span>
          {#if status.outdated}
            <p class="hint phone-approval-warning phone-approval-outdated" role="alert">
              {m.phone_approval_outdated()}
            </p>
          {/if}
          {#if status.relayRefusal}
            <p class="hint phone-approval-warning phone-approval-refusal" role="alert">
              {status.relayRefusal === "machine_limit"
                ? m.err_phone_machine_limit()
                : m.err_phone_subscription_required()}
            </p>
          {/if}
        </dd>
        {#if !status.outdated}
        <dt>{m.phone_approval_ask()}</dt>
        <dd>
          <label class="ssh-agent-autostart">
            <input
              type="checkbox"
              checked={options.enabled}
              disabled={busy}
              onchange={(e) =>
                apply({ ...options, enabled: (e.currentTarget as HTMLInputElement).checked })}
            />
            {m.phone_approval_ask_label()}
          </label>
          {#if options.enabled && confirmPolicy === "never"}
            <p class="hint phone-approval-warning">{m.phone_approval_needs_policy()}</p>
          {/if}
        </dd>
        <dt><label for="phone-approval-delay">{m.phone_approval_delay()}</label></dt>
        <dd>
          <input
            id="phone-approval-delay"
            class="phone-approval-delay"
            type="number"
            min="0"
            max="60"
            step="1"
            value={options.delayS}
            disabled={busy || !options.enabled}
            onchange={(e) => setDelay((e.currentTarget as HTMLInputElement).value)}
          />
          <p class="hint">{m.phone_approval_delay_hint()}</p>
        </dd>
        {/if}
      </dl>
      <p class="hint">{m.phone_approval_locked_vault()}</p>
    {/if}

    {#if offer}
      <div class="phone-approval-pairing" aria-live="polite">
        {#if candidate}
          <p>{m.phone_approval_compare({ name: candidate.deviceName || m.phone_approval_unnamed() })}</p>
          <p class="phone-approval-digits">{candidate.digits}</p>
          <div class="phone-approval-actions">
            <button type="button" class="secondary" onclick={cancelPairing} disabled={busy}>
              {m.phone_approval_digits_differ()}
            </button>
            <button type="button" onclick={confirmPairing} disabled={busy}>
              {m.phone_approval_digits_match()}
            </button>
          </div>
        {:else}
          <p>{m.phone_approval_scan()}</p>
          <!-- SVG rendered by the backend's QR encoder from the link: only
               rectangles, nothing from the relay but the code it encodes. -->
          <div class="phone-approval-qr">{@html offer.qrSvg}</div>
          <p class="hint">{m.phone_approval_or_code()}</p>
          <code class="phone-approval-code">{offer.code}</code>
          <p class="hint">{m.phone_approval_waiting()}</p>
          <div class="phone-approval-actions">
            <button type="button" class="secondary" onclick={cancelPairing}>
              {m.phone_approval_cancel()}
            </button>
          </div>
        {/if}
      </div>
    {:else if pairing && !status.paired}
      <form
        class="phone-approval-form"
        onsubmit={(e) => {
          e.preventDefault();
          startPairing();
        }}
      >
        <label>
          {m.phone_approval_relay()}
          <input type="url" bind:value={relay} required disabled={busy} />
        </label>
        <label>
          {m.phone_approval_enroll_secret()}
          <PasswordInput bind:value={enrollSecret} autocomplete="off" disabled={busy} />
          <span class="hint">{m.phone_approval_enroll_secret_hint()}</span>
        </label>
        <label>
          {m.phone_approval_label()}
          <input
            type="text"
            bind:value={label}
            required
            maxlength="64"
            placeholder={m.phone_approval_label_placeholder()}
            disabled={busy}
          />
        </label>
        <div class="phone-approval-actions">
          <button type="button" class="secondary" onclick={cancelPairing} disabled={busy}>
            {m.phone_approval_cancel()}
          </button>
          <button type="submit" disabled={busy}>{m.phone_approval_show_code()}</button>
        </div>
      </form>
    {:else}
      <div class="phone-approval-actions">
        {#if status.paired}
          <button type="button" class="secondary" onclick={forget} disabled={busy}>
            {m.phone_approval_forget()}
          </button>
          {#if !status.outdated}
            <button type="button" class="secondary" onclick={startPairing} disabled={busy}>
              {m.phone_approval_add()}
            </button>
          {/if}
        {:else}
          <button type="button" onclick={() => (pairing = true)} disabled={busy}>
            {m.phone_approval_pair()}
          </button>
        {/if}
      </div>
    {/if}

    {#if error}
      <p class="audit-error">{error}</p>
    {/if}
  </section>
{/if}

<style>
  .phone-approval {
    margin-top: 1.25rem;
    border-top: 1px solid var(--border);
    padding-top: 0.75rem;
  }
  .phone-approval h3 {
    margin: 0 0 0.25rem;
    font-size: 1rem;
  }
  .phone-approval-devices {
    margin: 0;
    padding-left: 1.1rem;
  }
  .phone-approval-delay {
    width: 5rem;
  }
  .phone-approval-warning {
    color: var(--warning-text);
  }
  .phone-approval-pairing,
  .phone-approval-form {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    margin-top: 0.5rem;
  }
  .phone-approval-qr {
    width: 200px;
    height: 200px;
    background: #fff; /* a QR code needs its light quiet zone in dark mode too */
    padding: 4px;
    border-radius: 6px;
  }
  .phone-approval-qr :global(svg) {
    width: 100%;
    height: 100%;
  }
  .phone-approval-code {
    word-break: break-all;
    font-size: 0.8rem;
  }
  .phone-approval-digits {
    font-family: monospace;
    font-size: 1.6rem;
    letter-spacing: 0.15em;
    margin: 0;
  }
  .phone-approval-actions {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
    margin-top: 0.5rem;
  }
</style>
