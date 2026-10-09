import { expect } from "vitest";

/** Official classes may render through shared adapters; never through modules. */
export function assertUx4gAdapters(container) {
  const unscoped = Array.from(container.querySelectorAll("[class]")).filter(
    (element) =>
      Array.from(element.classList).some((name) => name.startsWith("ux4g-")) &&
      !element.closest(".cc-ux4g"),
  );
  expect(unscoped.map((element) => element.outerHTML)).toEqual([]);
}
