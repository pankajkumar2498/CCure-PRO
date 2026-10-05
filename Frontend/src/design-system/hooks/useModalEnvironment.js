import { useLayoutEffect } from "react";

const roots = [];
const originals = new Map();
function sync() {
  const top = roots.at(-1);
  const blocked = new Set();
  // Isolate every sibling on the path to body. This also handles an inner
  // dialog portalled into a shared host rather than a separate body child.
  for (let branch = top; branch?.parentElement; branch = branch.parentElement) {
    for (const sibling of branch.parentElement.children)
      if (sibling !== branch) blocked.add(sibling);
    if (branch.parentElement === document.body) break;
  }
  for (const element of new Set([...originals.keys(), ...blocked])) {
    if (!originals.has(element))
      originals.set(element, {
        inert: element.getAttribute("inert"),
        hidden: element.getAttribute("aria-hidden"),
      });
    const original = originals.get(element);
    const isolate = blocked.has(element);
    for (const [attribute, value] of [
      ["inert", isolate ? "" : original.inert],
      ["aria-hidden", isolate ? "true" : original.hidden],
    ]) {
      if (value === null) element.removeAttribute(attribute);
      else element.setAttribute(attribute, value);
    }
  }
  if (!top) originals.clear();
}

/** Shared modal background isolation, including nested portals and late toasts. */
export default function useModalEnvironment(ref, active) {
  useLayoutEffect(() => {
    if (!active || !ref.current) return undefined;
    const root = ref.current;
    roots.push(root);
    sync();
    const observer = new MutationObserver(sync);
    observer.observe(document.body, { childList: true, subtree: true });
    return () => {
      observer.disconnect();
      const index = roots.indexOf(root);
      if (index >= 0) roots.splice(index, 1);
      sync();
    };
  }, [ref, active]);
}
