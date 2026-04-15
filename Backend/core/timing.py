"""
core/timing.py
--------------
Priority 3-J: Adaptive timing engine for network probes.

Adjusts per-target timeouts based on observed RTT samples so that
slow hosts get more time while fast LANs complete quickly.
Also provides a send_delay to help avoid IDS / rate-limiter triggers.
"""


class AdaptiveTimer:
    """
    Rolling-window RTT tracker that adapts probe timeouts and send delays.

    Usage::

        timer = AdaptiveTimer()

        # After each successful probe record the measured RTT:
        timer.record_rtt(elapsed_ms)

        # Before the next probe read the derived values:
        timeout    = timer.timeout      # seconds — use as asyncio/scapy timeout
        send_delay = timer.send_delay   # seconds — sleep between probe sends

    The window keeps the last ``_MAX_SAMPLES`` measurements so the timer adapts
    quickly to changing network conditions without being dragged down by stale
    outliers from the start of a scan.
    """

    _MAX_SAMPLES: int = 20  # rolling window depth

    def __init__(self) -> None:
        self.rtt_samples: list = []

    # ------------------------------------------------------------------
    # Measurement recording
    # ------------------------------------------------------------------

    def record_rtt(self, ms: float) -> None:
        """
        Record one round-trip-time measurement in *milliseconds*.

        Ignores non-positive values (measurement errors).
        Evicts the oldest sample when the window is full.
        """
        if ms > 0:
            self.rtt_samples.append(ms)
            if len(self.rtt_samples) > self._MAX_SAMPLES:
                self.rtt_samples.pop(0)

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def avg_rtt_ms(self) -> float:
        """Mean RTT in milliseconds. Returns 333 ms when no data is available."""
        if not self.rtt_samples:
            return 333.0
        return sum(self.rtt_samples) / len(self.rtt_samples)

    @property
    def timeout(self) -> float:
        """
        Recommended probe timeout in *seconds*.

        Formula: ``3 × avg_RTT``, clamped to **[0.5 s, 5.0 s]**.
        Falls back to **1.0 s** when no RTT data has been recorded yet.

        The 3× multiplier gives enough headroom for jitter while keeping
        scans snappy on low-latency LANs.
        """
        if not self.rtt_samples:
            return 1.0
        avg = self.avg_rtt_ms
        return max(0.5, min(avg * 3.0 / 1000.0, 5.0))

    @property
    def send_delay(self) -> float:
        """
        Recommended inter-probe delay in *seconds*.

        Uses ¹⁄₁₀ of the current timeout (floor **50 ms**) to gently pace
        probe bursts and reduce the chance of triggering IDS rate limiters
        or overwhelming a slow embedded-device network stack.
        """
        return max(0.05, self.timeout / 10.0)

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Clear all RTT samples and start fresh (e.g. for a new target)."""
        self.rtt_samples.clear()

    def __repr__(self) -> str:
        return (
            f"AdaptiveTimer("
            f"samples={len(self.rtt_samples)}, "
            f"avg_rtt={self.avg_rtt_ms:.1f}ms, "
            f"timeout={self.timeout:.2f}s, "
            f"send_delay={self.send_delay:.3f}s)"
        )
