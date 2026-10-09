import { useEffect, useState } from "react";

/** Shared presentation breakpoint. Never determines routing or permissions. */
export default function useMediaQuery(query) {
  const [matches, setMatches] = useState(() =>
    Boolean(window.matchMedia?.(query).matches),
  );
  useEffect(() => {
    const media = window.matchMedia?.(query);
    if (!media) return undefined;
    const change = () => setMatches(media.matches);
    change();
    media.addEventListener?.("change", change);
    return () => media.removeEventListener?.("change", change);
  }, [query]);
  return matches;
}
