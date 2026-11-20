// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";

vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: vi.fn() }));

import Onboarding from "./Onboarding.svelte";

afterEach(cleanup);

const buttons = () => Array.from(document.querySelectorAll<HTMLButtonElement>(".onboarding button"));

describe("Onboarding", () => {
  it("has its single button on a build without the phone features", async () => {
    const onComplete = vi.fn();
    render(Onboarding, { props: { onComplete } });
    expect(document.querySelector(".choices")).toBeNull();
    const start = buttons().at(-1)!;
    await fireEvent.click(start);
    expect(onComplete).toHaveBeenCalledTimes(1);
  });

  it("asks vault or phone only where both exist", async () => {
    const onComplete = vi.fn();
    const onPhoneOnly = vi.fn();
    render(Onboarding, { props: { onComplete, onPhoneOnly } });
    await fireEvent.click(document.querySelector(".choice-phone") as HTMLButtonElement);
    expect(onPhoneOnly).toHaveBeenCalledTimes(1);
    expect(onComplete).not.toHaveBeenCalled();
    await fireEvent.click(document.querySelector(".choice-vault") as HTMLButtonElement);
    expect(onComplete).toHaveBeenCalledTimes(1);
  });
});
