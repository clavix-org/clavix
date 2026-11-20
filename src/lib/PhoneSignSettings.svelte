<script lang="ts">
  // "Sign with the phone when the vault is locked": a second pairing, in
  // sign mode, whose phones sign with their own key (Face ID) through a
  // key-less agent Clavix runs while the vault is locked. Hidden entirely
  // in builds without the relay client (`phone-approval` feature).
  import { onMount } from "svelte";
  import * as m from "#lib/paraglide/messages.js";
  import { api } from "./api";
  import { formatError } from "./format";
  import PasswordInput from "./PasswordInput.svelte";
  import { DEFAULT_PHONE_RELAY } from "./phone";
  import type { PhonePairCandidate, PhonePairOffer, PhoneSignStatus } from "./types";

  let status = $state<PhoneSignStatus | null>(null);
  let busy = $state(false);
  let error = $state<string | null>(null);

  // Pairing form and flow.
  let pairing = $state(false);
  let relay = $state(DEFAULT_PHONE_RELAY);
  let enrollSecret = $state("");
  let label = $state("");
  let offer = $state<PhonePairOffer | null>(null);
  let candidate = $state<PhonePairCandidate | null>(null);

  // The key of the phone just paired, to install on servers.
  let newKey = $state<string | null>(null);
  let renewed = $state(false);
  let copied = $state<string | null>(null);
  // A phone the relay could not revoke: offer to forget it here only.
  let forgetFailed = $state<string | null>(null);

  onMount(() => {
    refresh();
    return () => {
      // Leaving the dialog mid-pairing: stop waiting on the relay, and
      // take a phone that answered but was never confirmed off it again.
      if (offer) api.phoneSignPairCancel().catch(() => {});
    };
  });

  async function refresh() {
    try {
      status = await api.phoneSignStatus();
    } catch (e) {
      error = formatError(e);
    }
  }

  async function startPairing() {
    busy = true;
    error = null;
    candidate = null;
    newKey = null;
    try {
      offer = await api.phoneSignPairStart(relay, enrollSecret, label);
    } catch (e) {
      error = formatError(e);
      busy = false;
      return;
    }
    busy = false;
    try {
      candidate = await api.phoneSignPairWait();
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
      const done = await api.phoneSignPairConfirm();
      status = done.status;
      newKey = done.publicKey;
      renewed = done.renewed;
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
    await api.phoneSignPairCancel().catch(() => {});
  }

  async function copy(key: string) {
    try {
      await api.clipboardWrite(key);
      copied = key;
    } catch (e) {
      error = formatError(e);
    }
  }

  async function forget(id: string, localOnly: boolean) {
    busy = true;
    error = null;
    try {
      status = await api.phoneSignForget(id, localOnly);
      forgetFailed = null;
      newKey = null;
    } catch (e) {
      error = formatError(e);
      if (!localOnly) forgetFailed = id;
    } finally {
      busy = false;
    }
  }

  async function setUseWhenLocked(enabled: boolean) {
    busy = true;
    error = null;
    try {
      status = await api.phoneSignSetUseWhenLocked(enabled);
    } catch (e) {
      error = formatError(e);
    } finally {
      busy = false;
    }
  }
</script>

{#if status?.available}
  <section class="phone-sign" aria-labelledby="phone-sign-title">
    <h3 id="phone-sign-title">{m.phone_sign_title()}</h3>
    <p class="hint">{m.phone_sign_intro()}</p>

    {#if status.paired}
      <dl class="phone-approval-setting">
        <dt>{m.phone_sign_devices()}</dt>
        <dd>
          <ul class="phone-sign-devices">
            {#each status.devices as device (device.id)}
              <li>
                <span class="phone-sign-name">{device.name || m.phone_approval_unnamed()}</span>
                <code class="phone-sign-fingerprint">{device.fingerprint}</code>
                <span class="phone-sign-device-actions">
                  <button
                    type="button"
                    class="secondary"
                    onclick={() => copy(device.publicKey)}
                    disabled={busy}
                  >
                    {copied === device.publicKey ? m.phone_sign_copied() : m.phone_sign_copy()}
                  </button>
                  <button
                    type="button"
                    class="secondary"
                    onclick={() => forget(device.id, false)}
                    disabled={busy}
                  >
                    {m.phone_sign_forget_one()}
                  </button>
                  {#if forgetFailed === device.id}
                    <button
                      type="button"
                      class="secondary phone-sign-forget-local"
                      onclick={() => forget(device.id, true)}
                      disabled={busy}
                    >
                      {m.phone_sign_forget_local()}
                    </button>
                  {/if}
                </span>
              </li>
            {/each}
          </ul>
          <span class="hint">{status.relay}</span>
          {#if status.outdated}
            <p class="hint phone-sign-warning phone-sign-outdated" role="alert">
              {m.phone_approval_outdated()}
            </p>
          {/if}
          {#if forgetFailed}
            <p class="hint phone-sign-warning" role="alert">
              {m.phone_sign_forget_local_warning()}
            </p>
          {/if}
          <p class="hint">{m.phone_sign_forget_hint()}</p>
        </dd>
        {#if !status.outdated}
        <dt>{m.phone_sign_when_locked()}</dt>
        <dd>
          <label class="ssh-agent-autostart">
            <input
              type="checkbox"
              class="phone-sign-use"
              checked={status.useWhenLocked}
              disabled={busy}
              onchange={(e) => setUseWhenLocked((e.currentTarget as HTMLInputElement).checked)}
            />
            {m.phone_sign_use_when_locked()}
          </label>
          <p class="hint">{m.phone_sign_use_hint()}</p>
        </dd>
        {/if}
      </dl>
    {/if}

    {#if newKey}
      <div class="phone-sign-new-key" aria-live="polite">
        {#if renewed}
          <p>{m.phone_sign_renewed()}</p>
        {:else}
          <p>{m.phone_sign_pubkey_title()}</p>
          <code class="phone-sign-pubkey">{newKey}</code>
          <div class="phone-approval-actions">
            <button type="button" class="secondary" onclick={() => copy(newKey!)}>
              {copied === newKey ? m.phone_sign_copied() : m.phone_sign_copy()}
            </button>
            <button type="button" onclick={() => (newKey = null)}>{m.phone_sign_done()}</button>
          </div>
        {/if}
      </div>
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
        class="phone-sign-form"
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
          {#if !status.outdated}
            <button type="button" class="secondary" onclick={startPairing} disabled={busy}>
              {m.phone_sign_add()}
            </button>
          {/if}
        {:else}
          <button type="button" onclick={() => (pairing = true)} disabled={busy}>
            {m.phone_sign_pair()}
          </button>
        {/if}
      </div>
    {/if}

    <p class="hint">{m.phone_sign_storage()}</p>

    {#if error}
      <p class="audit-error">{error}</p>
    {/if}
  </section>
{/if}

<style>
  .phone-sign-warning {
    color: var(--warning-text);
  }
  .phone-sign {
    margin-top: 1.25rem;
    border-top: 1px solid var(--border);
    padding-top: 0.75rem;
  }
  .phone-sign h3 {
    margin: 0 0 0.25rem;
    font-size: 1rem;
  }
  .phone-sign-devices {
    margin: 0;
    padding-left: 1.1rem;
  }
  .phone-sign-devices li {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.3rem;
  }
  .phone-sign-fingerprint,
  .phone-sign-pubkey,
  .phone-approval-code {
    word-break: break-all;
    font-size: 0.8rem;
  }
  .phone-sign-device-actions {
    display: inline-flex;
    gap: 0.4rem;
  }
  .phone-sign-new-key,
  .phone-approval-pairing,
  .phone-sign-form {
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
