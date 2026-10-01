import { useState, useEffect, useCallback, useRef } from "react";
import { webScansApi } from "../api/webScansApi";

/**
 * Hook to poll a specific Web Scan's status and automatically fetch updates.
 *
 * @param {string} scanId - The ID of the scan to poll
 * @param {number} intervalMs - Polling interval in milliseconds (default 5000)
 * @returns {object} { scan, loading, error, refresh }
 */
export function useScanPolling(scanId, intervalMs = 5000) {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [liveStatus, setLiveStatus] = useState("connecting");
  const [liveEvents, setLiveEvents] = useState([]);
  const timerRef = useRef(null);
  const socketRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const terminalRef = useRef(false);
  const isMountedRef = useRef(true);

  const fetchScan = useCallback(async () => {
    if (!scanId) return;

    try {
      const response = await webScansApi.getScan(scanId);
      const scanData = response.data?.data || response.data;
      if (isMountedRef.current) {
        setScan(scanData);
        setError(null);
        setLoading(false);
      }
      return scanData;
    } catch (err) {
      if (isMountedRef.current) {
        console.error("Error fetching web scan:", err);
        setError(err?.response?.data?.detail || "Failed to load scan data.");
        setLoading(false);
      }
      return null;
    }
  }, [scanId]);

  useEffect(() => {
    isMountedRef.current = true;
    terminalRef.current = false;
    setLoading(true);
    fetchScan();

    const startPollingFallback = () => {
      if (timerRef.current) return;

      const poll = async () => {
        timerRef.current = null;
        const currentScan = await fetchScan();
        const isActive =
          currentScan &&
          ["running", "pending", "queued"].includes(
            String(currentScan.status || "").toLowerCase(),
          );

        if (isActive && isMountedRef.current) {
          timerRef.current = setTimeout(poll, intervalMs);
        }
      };

      timerRef.current = setTimeout(poll, intervalMs);
    };

    const connectLiveProgress = async () => {
      if (!scanId || !isMountedRef.current) return;

      try {
        setLiveStatus("connecting");
        const ticketResponse = await webScansApi.getProgressTicket();
        const ticket = ticketResponse.data?.ticket;
        if (!ticket) throw new Error("Missing progress ticket");

        const ws = new WebSocket(
          webScansApi.getProgressSocketUrl(scanId, ticket),
        );
        socketRef.current = ws;

        ws.onopen = () => {
          if (!isMountedRef.current) return;
          setLiveStatus("connected");
        };

        ws.onmessage = (event) => {
          if (!isMountedRef.current) return;
          try {
            const payload = JSON.parse(event.data);
            const progress = payload.progress || {};
            const partialScan = payload.scan || {};
            const phase = progress.phase || payload.phase;

            setLiveEvents((prev) =>
              [
                {
                  id: `${Date.now()}-${prev.length}`,
                  phase,
                  status: progress.status,
                  message:
                    progress.message || `Phase ${phase || "scan"} updated.`,
                  emitted_at: progress.updated_at || new Date().toISOString(),
                },
                ...prev,
              ].slice(0, 12),
            );

            setScan((prev) => ({
              ...(prev || {}),
              ...partialScan,
              status: progress.status || partialScan.status || prev?.status,
              pipeline_phase:
                phase || partialScan.pipeline_phase || prev?.pipeline_phase,
              total_endpoints:
                progress.total_endpoints ??
                partialScan.total_endpoints ??
                prev?.total_endpoints,
              total_findings:
                progress.total_findings ??
                partialScan.total_findings ??
                prev?.total_findings,
              live_progress: progress,
            }));

            const nextStatus = String(
              progress.status || partialScan.status || "",
            ).toLowerCase();
            if (
              ["complete", "completed", "failed", "cancelled"].includes(
                nextStatus,
              )
            ) {
              terminalRef.current = true;
              fetchScan();
              ws.close();
            }
          } catch (err) {
            console.error("Invalid web scan progress message:", err);
          }
        };

        ws.onerror = () => {
          if (!isMountedRef.current) return;
          setLiveStatus("degraded");
          startPollingFallback();
        };

        ws.onclose = () => {
          if (!isMountedRef.current) return;
          if (terminalRef.current) {
            setLiveStatus("closed");
            return;
          }
          setLiveStatus((current) =>
            current === "connected" ? "reconnecting" : "degraded",
          );
          startPollingFallback();
          reconnectTimerRef.current = setTimeout(
            connectLiveProgress,
            Math.max(intervalMs, 5000),
          );
        };
      } catch (err) {
        if (!isMountedRef.current) return;
        console.error("Failed to start web scan progress socket:", err);
        setLiveStatus("degraded");
        startPollingFallback();
      }
    };

    connectLiveProgress();

    return () => {
      isMountedRef.current = false;
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
    };
  }, [fetchScan, intervalMs, scanId]);

  const refresh = () => fetchScan();

  return { scan, loading, error, refresh, liveStatus, liveEvents };
}
