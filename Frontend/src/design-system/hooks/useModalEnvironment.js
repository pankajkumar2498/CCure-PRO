import { useEffect } from "react";

const roots = [];
const originals = new Map();
function sync() {
  const top = roots.at(-1);
  for (const element of document.body.children) {
    if (!originals.has(element))
      originals.set(element, {
        inert: element.getAttribute("inert"),
        hidden: element.getAttribute("aria-hidden"),
      });
    const original = originals.get(element);
    const blocked = top && !element.contains(top);
    for (const [attribute, value] of [
      ["inert", blocked ? "" : original.inert],
      ["aria-hidden", blocked ? "true" : original.hidden],
    ]) {
      if (value === null) element.removeAttribute(attribute);
      else element.setAttribute(attribute, value);
    }
  }
  if (!top) originals.clear();
}

/** Shared modal background isolation, including nested portals and late toasts. */
export default function useModalEnvironment(ref, active) {
  useEffect(() => {
    if (!active || !ref.current) return undefined;
    const root = ref.current;
    roots.push(root);
    sync();
    const observer = new MutationObserver(sync);
    observer.observe(document.body, { childList: true });
    return () => {
      observer.disconnect();
      const index = roots.indexOf(root);
      if (index >= 0) roots.splice(index, 1);
      sync();
    };
  }, [ref, active]);
}
