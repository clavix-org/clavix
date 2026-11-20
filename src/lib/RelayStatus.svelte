<script lang="ts">
  import { onDestroy, onMount, untrack } from "svelte";
  import * as m from "#lib/paraglide/messages.js";
  import { api } from "./api";
  import type { RelayHealth } from "./types";

  // The relay keeps no connection open: Clavix reaches it once per SSH
  // request. So the indicator asks the back end to knock on each relay
  // in use (`/healthz`, no token) now and then, and shows nothing at all
  // while no phone is paired.
  const EVERY_MS = 60_000;

  type Props = {
    /** A divider after the indicator, before what follows it (toolbar). */
    separator?: boolean;
    /** Probe again whenever this changes (a phone paired or forgotten),
        rather than at the next minute. */
    refresh?: unknown;
  };
  let { separator = false, refresh }: Props = $props();

  type Kind = "ok" | "refused" | "unreachable";

  let health = $state<RelayHealth[]>([]);
  let inFlight = false;
  // A probe asked for while one runs (a phone just paired) runs after it
  // instead of being dropped.
  let again = false;

  async function probe() {
    // A window hidden in the tray needs no indicator; it probes again
    // when shown.
    if (document.hidden) return;
    if (inFlight) {
      again = true;
      return;
    }
    inFlight = true;
    try {
      health = await api.phoneRelayHealth();
    } catch {
      health = [];
    } finally {
      inFlight = false;
    }
    if (again) {
      again = false;
      void probe();
    }
  }

  const onVisibility = () => {
    if (!document.hidden) void probe();
  };

  let timer: ReturnType<typeof setInterval> | undefined;
  $effect(() => {
    void refresh;
    untrack(() => void probe());
  });

  onMount(() => {
    timer = setInterval(() => void probe(), EVERY_MS);
    document.addEventListener("visibilitychange", onVisibility);
  });
  onDestroy(() => {
    clearInterval(timer);
    document.removeEventListener("visibilitychange", onVisibility);
  });

  // The worst relay sets the colour: unreachable over refused over ok.
  let kind = $derived<Kind | null>(
    health.length === 0
      ? null
      : health.some((h) => !h.reachable)
        ? "unreachable"
        : health.some((h) => h.refusal !== null)
          ? "refused"
          : "ok",
  );

  let label = $derived.by(() => {
    switch (kind) {
      case "ok":
        return m.relay_status_ok();
      case "refused":
        return m.relay_status_refused();
      case "unreachable":
        return m.relay_status_unreachable();
      default:
        return "";
    }
  });

  function host(url: string): string {
    try {
      return new URL(url).host;
    } catch {
      return url;
    }
  }

  let title = $derived.by(() => {
    if (kind === null) return "";
    const lines = [m.relay_status_title({ relays: health.map((h) => host(h.relay)).join(", ") })];
    const refusal = health.find((h) => h.refusal !== null)?.refusal;
    if (refusal === "machine_limit") lines.push(m.err_phone_machine_limit());
    else if (refusal === "subscription_required") lines.push(m.err_phone_subscription_required());
    return lines.join("\n");
  });

  // Announced when the kind changes, not at every probe.
  let announced = $state("");
  $effect(() => {
    void kind;
    announced = untrack(() => label);
  });
</script>

{#if kind !== null}
  <div class="relay" title={title} data-testid="relay-status">
    <span class="dot dot--{kind}" aria-hidden="true"></span>
    <span class="label" aria-hidden="true">{label}</span>
    <span class="visually-hidden" aria-live="polite">{announced}</span>
  </div>
  {#if separator}
    <span class="sep" aria-hidden="true"></span>
  {/if}
{/if}

<style>
  .relay {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    cursor: default;
  }

  .label {
    font-weight: 500;
  }

  .sep {
    width: 1px;
    height: 0.9rem;
    background: var(--border-accent);
    margin: 0 0.25rem;
  }

  /* Same dots, colours and halos as the sync indicator next to it. */
  .dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
    flex: 0 0 auto;
    transition:
      background-color 150ms ease,
      box-shadow 150ms ease;
  }
  .dot--ok {
    background: var(--status-fresh);
    box-shadow: 0 0 0 2px rgba(34, 197, 94, 0.2);
  }
  .dot--refused {
    background: var(--status-busy);
    box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.2);
  }
  .dot--unreachable {
    background: var(--status-offline);
    box-shadow: 0 0 0 2px rgba(239, 68, 68, 0.2);
  }

  /* Same breakpoint as the sync sentence: the dot and its tooltip stay. */
  @media (max-width: 760px) {
    .label {
      display: none;
    }
  }
</style>
