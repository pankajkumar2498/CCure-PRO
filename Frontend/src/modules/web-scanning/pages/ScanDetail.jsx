import { useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import AppLayout from "../../../components/layout/AppLayout";
import { useScanPolling } from "../hooks/useScanPolling";
import { webScansApi } from "../api/webScansApi";
import Skeleton from "../../../components/common/Skeleton";

const PIPELINE_PHASES = ["RECON", "CRAWL", "DETECT", "AUDIT"];
const ACTIVE_STATUSES = new Set(["queued", "pending", "running"]);
const COMPLETE_STATUSES = new Set(["complete", "completed"]);

const SvgCheck = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>;
const SvgSpinner = () => (
  <svg className="spinner-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ animation: 'spin 1s linear infinite' }}>
    <line x1="12" y1="2" x2="12" y2="6"></line>
    <line x1="12" y1="18" x2="12" y2="22"></line>
    <line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line>
    <line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line>
    <line x1="2" y1="12" x2="6" y2="12"></line>
    <line x1="18" y1="12" x2="22" y2="12"></line>
    <line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line>
    <line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line>
  </svg>
);

export default function ScanDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { scan, loading, error, refresh, liveStatus, liveEvents } = useScanPolling(id, 5000);
  const [downloading, setDownloading] = useState(false);

  const handleDownload = async () => {
    try {
      setDownloading(true);
      const res = await webScansApi.downloadReport(id);
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `WebScanReport_${id}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      console.error("Failed to download PDF", err);
      alert("Failed to generate report.");
    } finally {
      setDownloading(false);
    }
  };

  const handleCancel = async () => {
    if (window.confirm("Are you sure you want to cancel this scan?")) {
      await webScansApi.cancelScan(id);
      refresh();
    }
  };

  if (loading && !scan) {
    return (
      <AppLayout pageTitle="Scan Details">
        <div className="page-inner" style={{ maxWidth: '1200px', margin: '0 auto', padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <Skeleton height="60px" borderRadius="8px" />
          <Skeleton height="150px" borderRadius="12px" />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px' }}>
            <Skeleton height="100px" borderRadius="12px" />
            <Skeleton height="100px" borderRadius="12px" />
            <Skeleton height="100px" borderRadius="12px" />
            <Skeleton height="100px" borderRadius="12px" />
          </div>
          <div style={{ display: 'flex', gap: '20px' }}>
             <Skeleton height="120px" borderRadius="12px" />
             <Skeleton height="120px" borderRadius="12px" />
          </div>
        </div>
      </AppLayout>
    );
  }

  if (error) {
    return (
      <AppLayout pageTitle="Scan Details">
        <div style={{ padding: '24px', color: 'var(--danger)' }}>{error}</div>
      </AppLayout>
    );
  }

  if (!scan) return null;

  const normalizedStatus = String(scan.status || "").toLowerCase();
  const normalizedPhase = String(scan.pipeline_phase || "").toUpperCase();
  const isActiveScan = ACTIVE_STATUSES.has(normalizedStatus);
  const isCompleteScan = COMPLETE_STATUSES.has(normalizedStatus);
  const currentPhaseIndex = PIPELINE_PHASES.indexOf(normalizedPhase);
  const progressPercent = scan.live_progress?.percentage ?? (isCompleteScan ? 100 : Math.max(0, currentPhaseIndex) * 33.33);
  const liveStatusLabel = {
    connected: "Live",
    connecting: "Connecting",
    reconnecting: "Reconnecting",
    degraded: "Polling",
    closed: "Closed",
  }[liveStatus] || "Polling";

  return (
    <AppLayout pageTitle={`Scan: ${scan.scan_name}`}>
      <div className="page-inner" style={{ maxWidth: '1200px', margin: '0 auto', padding: '24px' }}>
        
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '24px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
              <h1 className="page-title" style={{ margin: 0 }}>{scan.scan_name}</h1>
              <span style={{ 
                padding: '4px 10px', borderRadius: '12px', fontSize: '0.75rem', fontWeight: 'bold', textTransform: 'uppercase',
                background: isCompleteScan ? 'var(--ok-bg, rgba(34,197,94,0.15))' : 'var(--info-bg, rgba(59,130,246,0.15))',
                color: isCompleteScan ? 'var(--ok)' : 'var(--info)',
                border: `1px solid ${isCompleteScan ? 'var(--ok)' : 'var(--info)'}40`
              }}>
                {scan.status}
              </span>
              <span style={{
                padding: '4px 10px', borderRadius: '12px', fontSize: '0.75rem', fontWeight: 'bold', textTransform: 'uppercase',
                background: liveStatus === "connected" ? 'rgba(34,197,94,0.12)' : 'rgba(245,158,11,0.12)',
                color: liveStatus === "connected" ? 'var(--ok)' : 'var(--warning)',
                border: `1px solid ${liveStatus === "connected" ? 'var(--ok)' : 'var(--warning)'}40`
              }}>
                {liveStatusLabel}
              </span>
            </div>
            <p className="page-subtitle" style={{ fontSize: '1rem' }}>
              Target: <a href={scan.target_url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', textDecoration: 'none' }}>{scan.target_url}</a>
            </p>
          </div>
          
          <div style={{ display: 'flex', gap: '12px' }}>
             {isActiveScan && (
               <button className="btn btn--outline" onClick={handleCancel} style={{ color: 'var(--danger)', borderColor: 'var(--danger)' }}>
                 Cancel Scan
               </button>
             )}
             {isCompleteScan && (
               <button className="btn btn--primary" onClick={handleDownload} disabled={downloading}>
                 {downloading ? "Generating PDF..." : "Download Report"}
               </button>
             )}
          </div>
        </div>

        {/* Stepper */}
        <div style={{ background: 'var(--bg-panel)', padding: '24px', borderRadius: '12px', border: '1px solid var(--border)', marginBottom: '24px' }}>
           <h3 style={{ fontSize: '0.9rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '16px' }}>Pipeline Progress</h3>
           {isActiveScan && (
             <div role="status" aria-live="polite" style={{ marginBottom: '16px', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
               {scan.live_progress?.message || `Scan is ${normalizedStatus === "queued" ? "queued" : "running"} in the ${normalizedPhase.toLowerCase() || "initializing"} phase.`} This page updates automatically.
             </div>
           )}
           <div style={{ marginBottom: '16px' }}>
             <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '6px' }}>
               <span>Overall progress</span>
               <span>{Math.round(progressPercent)}%</span>
             </div>
             <div style={{ height: '8px', borderRadius: '999px', background: 'var(--bg-app)', overflow: 'hidden', border: '1px solid var(--border)' }}>
               <div style={{ width: `${Math.max(0, Math.min(100, progressPercent))}%`, height: '100%', background: isCompleteScan ? 'var(--ok)' : 'var(--accent)', transition: 'width 0.4s ease' }} />
             </div>
           </div>
           <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', position: 'relative' }}>
             {/* Track */}
             <div style={{ position: 'absolute', top: '50%', left: '0', right: '0', height: '2px', background: 'var(--border)', zIndex: 0, transform: 'translateY(-50%)' }}></div>
             <div style={{ position: 'absolute', top: '50%', left: '0', width: `${progressPercent}%`, height: '2px', background: 'var(--accent)', zIndex: 1, transform: 'translateY(-50%)', transition: 'width 0.5s ease' }}></div>
             
             {PIPELINE_PHASES.map((phase, idx) => {
               const isActive = normalizedPhase === phase && isActiveScan;
               const isDone = idx < currentPhaseIndex || isCompleteScan || normalizedPhase === "COMPLETE";
               
               return (
                 <div key={phase} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 2, background: 'var(--bg-panel)', padding: '0 10px' }}>
                   <div style={{ 
                     width: '32px', height: '32px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                     background: isDone ? 'var(--accent)' : isActive ? 'var(--bg-app)' : 'var(--bg-app)',
                     border: `2px solid ${isDone || isActive ? 'var(--accent)' : 'var(--border)'}`,
                     color: isDone ? '#fff' : isActive ? 'var(--accent)' : 'var(--text-muted)'
                   }}>
                     {isDone ? <SvgCheck /> : isActive ? <SvgSpinner /> : (idx + 1)}
                   </div>
                   <span style={{ fontSize: '0.8rem', fontWeight: isActive || isDone ? '600' : '400', color: isActive || isDone ? 'var(--text)' : 'var(--text-muted)' }}>
                     {phase}
                   </span>
                 </div>
               );
             })}
           </div>
        </div>

        {isActiveScan && (
          <div style={{ background: 'var(--bg-panel)', padding: '20px', borderRadius: '12px', border: '1px solid var(--border)', marginBottom: '24px' }}>
            <h3 style={{ fontSize: '0.9rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '12px' }}>Live Activity</h3>
            {liveEvents.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Waiting for scanner activity...</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {liveEvents.map((event) => (
                  <div key={event.id} style={{ display: 'grid', gridTemplateColumns: '110px 1fr', gap: '12px', fontSize: '0.88rem' }}>
                    <span style={{ color: 'var(--text-muted)', textTransform: 'uppercase' }}>{event.phase || 'scan'}</span>
                    <span style={{ color: 'var(--text)' }}>{event.message}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Overview Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginBottom: '24px' }}>
          <div style={{ background: 'var(--bg-panel)', padding: '20px', borderRadius: '12px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Discovered Assets</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 'bold' }}>{scan.total_endpoints || 0}</div>
          </div>
          <div style={{ background: 'var(--bg-panel)', padding: '20px', borderRadius: '12px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Critical Findings</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: scan.critical_count > 0 ? 'var(--danger)' : 'var(--text)' }}>{scan.critical_count || 0}</div>
          </div>
          <div style={{ background: 'var(--bg-panel)', padding: '20px', borderRadius: '12px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '8px' }}>High Findings</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: scan.high_count > 0 ? 'var(--warning)' : 'var(--text)' }}>{scan.high_count || 0}</div>
          </div>
          <div style={{ background: 'var(--bg-panel)', padding: '20px', borderRadius: '12px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Total Findings</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 'bold' }}>{scan.total_findings || 0}</div>
          </div>
        </div>

        {/* Action Links */}
        <div style={{ display: 'flex', gap: '20px' }}>
          <Link to={`/web-scans/${scan.id}/findings`} style={{ flex: 1, textDecoration: 'none' }}>
            <div style={{ background: 'var(--bg-panel)', padding: '24px', borderRadius: '12px', border: '1px solid var(--border)', transition: 'border-color 0.2s', cursor: 'pointer' }}>
              <h3 style={{ color: 'var(--accent)', marginBottom: '8px' }}>Explore Findings →</h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Deep dive into discovered vulnerabilities, HTTP evidence, and remediation steps.</p>
            </div>
          </Link>
          <Link to={`/web-scans/${scan.id}/assets`} style={{ flex: 1, textDecoration: 'none' }}>
            <div style={{ background: 'var(--bg-panel)', padding: '24px', borderRadius: '12px', border: '1px solid var(--border)', transition: 'border-color 0.2s', cursor: 'pointer' }}>
              <h3 style={{ color: 'var(--accent)', marginBottom: '8px' }}>Asset Inventory →</h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Review discovered endpoints, APIs, forms, and technologies.</p>
            </div>
          </Link>
        </div>

      </div>
    </AppLayout>
  );
}
