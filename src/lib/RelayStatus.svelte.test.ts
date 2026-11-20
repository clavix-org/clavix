// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";

const apiMock = vi.hoisted(() => ({
  phoneRelayHealth: vi.fn(),
}));
vi.mock("./api", () => ({ api: apiMock }));

import RelayStatus from "./RelayStatus.svelte";

const RELAY = "https://relay.example";

async function flush() {
  for (let i = 0; i < 5; i++) {
    await Promise.resolve();
    await tick();
  }
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.useRealTimers();
});

describe("RelayStatus", () => {
  it("shows nothing while no phone is paired", async () => {
    apiMock.phoneRelayHealth.mockResolvedValue([]);
    const { queryByTestId } = render(RelayStatus);
    await flush();
    expect(queryByTestId("relay-status")).toBeNull();
  });

  it("says connected when every relay answers", async () => {
    apiMock.phoneRelayHealth.mockResolvedValue([{ relay: RELAY, reachable: true, refusal: null }]);
    const { getByTestId } = render(RelayStatus);
    await flush();
    const el = getByTestId("relay-status");
    expect(el.querySelector(".dot--ok")).not.toBeNull();
    expect(el.getAttribute("title")).toContain("relay.example");
  });

  it("an unreachable relay wins over a refusal", async () => {
    apiMock.phoneRelayHealth.mockResolvedValue([
      { relay: RELAY, reachable: true, refusal: "subscription_required" },
      { relay: "https://other.example", reachable: false, refusal: null },
    ]);
    const { getByTestId } = render(RelayStatus);
    await flush();
    expect(getByTestId("relay-status").querySelector(".dot--unreachable")).not.toBeNull();
  });

  it("a refusal says what to do in the tooltip", async () => {
    apiMock.phoneRelayHealth.mockResolvedValue([
      { relay: RELAY, reachable: true, refusal: "machine_limit" },
    ]);
    const { getByTestId } = render(RelayStatus);
    await flush();
    const el = getByTestId("relay-status");
    expect(el.querySelector(".dot--refused")).not.toBeNull();
    expect(el.getAttribute("title")?.split("\n")).toHaveLength(2);
  });

  it("probes again every minute", async () => {
    vi.useFakeTimers();
    apiMock.phoneRelayHealth.mockResolvedValue([{ relay: RELAY, reachable: true, refusal: null }]);
    render(RelayStatus);
    await flush();
    expect(apiMock.phoneRelayHealth).toHaveBeenCalledTimes(1);
    apiMock.phoneRelayHealth.mockResolvedValue([{ relay: RELAY, reachable: false, refusal: null }]);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(apiMock.phoneRelayHealth).toHaveBeenCalledTimes(2);
  });
});
