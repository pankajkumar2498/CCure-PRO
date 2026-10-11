import { useEffect, useState } from "react";
import { isSelfRegistrationEnabled } from "@shell/api/auth";

// Fetch on every visit. Persisting a flag could expose a stale signup link
// after configuration changes; a response from an unmounted visit must not
// overwrite the current visit or retry.
export function useSelfRegistration() {
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState({ allowed: null, loading: true });

  useEffect(() => {
    let cancelled = false;
    const settle = (allowed) => {
      if (!cancelled) {
        setState({
          allowed: typeof allowed === "boolean" ? allowed : null,
          loading: false,
        });
      }
    };
    isSelfRegistrationEnabled().then(settle, () => settle(null));
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  return {
    ...state,
    retry: () => {
      setState({ allowed: null, loading: true });
      setAttempt((value) => value + 1);
    },
    disable: () => setState({ allowed: false, loading: false }),
  };
}
