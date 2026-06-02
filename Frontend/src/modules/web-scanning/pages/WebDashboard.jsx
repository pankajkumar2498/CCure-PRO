import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../../../components/layout/AppLayout";
import { webDashboardApi } from "../api/webScansApi";
import Skeleton from "../../../components/common/Skeleton";

const SvgGlobe = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"></circle>
    <line x1="2" y1="12" x2="22" y2="12"></line>
    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
  </svg>
);

const MetricCard = ({ title, value, icon, color }) => (
  <div className="stat-card" style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '20px', borderRadius: '12px', border: '1px solid var(--border)', background: 'var(--bg-panel)' }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)', fontWeight: '600' }}>{title}</span>
      <span style={{ color: color }}>{icon}</span>
    </div>
    <div style={{ fontSize: '2rem', fontWeight: 'bold', color: 'var(--text)' }}>
      {value}
    </div>
  </div>
);

export default function WebDashboard() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [summary, setSummary] = useState(null);
  const [scorecard, setScorecard] = useState(null);
  const [trends, setTrends] = useState(null);

  useEffect(() => {
    async function fetchData() {
      try {
        setLoading(true);
        const [sumRes, scoreRes, trendRes] = await Promise.all([
          webDashboardApi.getSummary(),
          webDashboardApi.getOwaspScorecard(),
          webDashboardApi.getTrends()
        ]);
        setSummary(sumRes.data);
        setScorecard(scoreRes.data);
        setTrends(trendRes.data);
      } catch (err) {
        console.error("Failed to load web dashboard data", err);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  return (
    <AppLayout pageTitle="Web Application Scanning">
      <div className="page-inner" style={{ maxWidth: '1400px', margin: '0 auto', padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '32px' }}>
          <div>
            <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span style={{ color: 'var(--accent)' }}><SvgGlobe /></span>
              Web Application Security
            </h1>
            <p className="page-subtitle">Dynamic Application Security Testing (DAST) Overview</p>
          </div>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button className="btn btn--outline" onClick={() => navigate("/web-scans/list")}>
              View All Scans
            </button>
            <button className="btn btn--primary" onClick={() => navigate("/web-scans/new")}>
              + New Web Scan
            </button>
          </div>
        </div>

        {loading ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px' }}>
               <Skeleton height="120px" borderRadius="12px" />
               <Skeleton height="120px" borderRadius="12px" />
               <Skeleton height="120px" borderRadius="12px" />
               <Skeleton height="120px" borderRadius="12px" />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
               <Skeleton height="300px" borderRadius="12px" />
               <Skeleton height="300px" borderRadius="12px" />
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {/* Top Metrics Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px' }}>
              <MetricCard 
                title="Active Web Scans" 
                value={summary?.active_scans || 0} 
                icon={<SvgGlobe />} 
                color="var(--accent)" 
              />
              <MetricCard 
                title="Critical Vulnerabilities" 
                value={summary?.critical_vulnerabilities || 0} 
                icon={<span style={{ fontSize: '1.2rem' }}>🔴</span>} 
                color="var(--danger)" 
              />
              <MetricCard 
                title="Total Endpoints Discovered" 
                value={summary?.total_endpoints || 0} 
                icon={<span style={{ fontSize: '1.2rem' }}>🔌</span>} 
                color="var(--info)" 
              />
              <MetricCard 
                title="Scans Last 30 Days" 
                value={summary?.scans_last_30_days || 0} 
                icon={<span style={{ fontSize: '1.2rem' }}>📅</span>} 
                color="var(--text-muted)" 
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
              {/* OWASP Scorecard Widget */}
              <div style={{ padding: '24px', borderRadius: '12px', border: '1px solid var(--border)', background: 'var(--bg-panel)' }}>
                <h3 style={{ marginBottom: '20px', fontSize: '1.1rem' }}>OWASP Top 10 Coverage</h3>
                {scorecard && scorecard.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {scorecard.slice(0, 5).map(item => (
                      <div key={item.category} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
                        <span style={{ fontSize: '0.9rem', color: 'var(--text)' }}>{item.category}</span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ fontSize: '0.8rem', fontWeight: 'bold', color: item.count > 0 ? 'var(--danger)' : 'var(--ok)' }}>
                            {item.count} findings
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', fontStyle: 'italic' }}>No OWASP findings detected yet.</div>
                )}
              </div>

              {/* Finding Trends Widget */}
              <div style={{ padding: '24px', borderRadius: '12px', border: '1px solid var(--border)', background: 'var(--bg-panel)' }}>
                <h3 style={{ marginBottom: '20px', fontSize: '1.1rem' }}>Vulnerability Trends (30 Days)</h3>
                {trends && trends.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {trends.slice(0, 5).map(trend => (
                      <div key={trend.date} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
                        <span style={{ fontSize: '0.9rem', color: 'var(--text)' }}>{trend.date}</span>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          {trend.critical > 0 && <span style={{ fontSize: '0.8rem', color: 'var(--danger)' }}>{trend.critical} Crit</span>}
                          {trend.high > 0 && <span style={{ fontSize: '0.8rem', color: 'var(--warning)' }}>{trend.high} High</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                   <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem', fontStyle: 'italic' }}>No trend data available.</div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
