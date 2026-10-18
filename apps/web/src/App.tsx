import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

type Severity = 'critical' | 'high' | 'medium' | 'low';
type HostState = 'healthy' | 'attention' | 'critical';

type DashboardSummary = {
  mode: 'simulated';
  generatedAt: string;
  metrics: {
    managedHosts: number;
    hostsNeedingAttention: number;
    pendingUpdates: number;
    securityUpdates: number;
    networkDetections: number;
    criticalDetections: number;
  };
  trend: { time: string; observed: number; detections: number }[];
  fleet: {
    id: string;
    hostname: string;
    address: string;
    distribution: string;
    release: string;
    environment: string;
    state: HostState;
    cpuPercent: number;
    memoryPercent: number;
    diskPercent: number;
    pendingUpdates: number;
    securityUpdates: number;
    lastSeen: string;
  }[];
  findings: {
    id: string;
    severity: Severity;
    title: string;
    description: string;
    source: string;
    destination: string;
    host: string;
    detector: string;
    observedAt: string;
    state: 'new' | 'investigating' | 'reviewed';
  }[];
  patches: {
    id: string;
    host: string;
    packageName: string;
    currentVersion: string;
    candidateVersion: string;
    advisory: string;
    severity: Severity;
    rebootRequired: boolean;
    recommendation: string;
  }[];
};

type ApiEnvelope = {
  success: boolean;
  data?: DashboardSummary;
  meta?: { mode?: string; notice?: string };
};

type LoadState = 'loading' | 'ready' | 'unavailable';

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:4000/api/v1';
const DashboardActivityChart = lazy(() => import('./DashboardActivityChart'));
const PatchReviewDialog = lazy(() => import('./PatchReviewDialog'));
const SocCopilotDialog = lazy(() => import('./SocCopilotDialog'));
const AdminOperationsPanel = lazy(() => import('./AdminOperationsPanel'));

const navItems = [
  { id: 'overview', label: 'Overview', icon: '◫' },
  { id: 'fleet', label: 'Linux fleet', icon: '▤' },
  { id: 'detections', label: 'Endpoint SIEM', icon: '⌁', count: '12' },
  { id: 'patches', label: 'Patch center', icon: '↻', count: '7' },
  { id: 'admin-console', label: 'Admin operations', icon: '⚙' },
];

export default function App() {
  const [activeSection, setActiveSection] = useState(window.location.hash.slice(1) || 'overview');
  const [dashboard, setDashboard] = useState<DashboardSummary | null>(null);
  const [loadState, setLoadState] = useState<LoadState>('loading');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [search, setSearch] = useState('');
  const [hostFilter, setHostFilter] = useState<'all' | HostState>('all');
  const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all');
  const [selectedPatch, setSelectedPatch] = useState<DashboardSummary['patches'][number] | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<DashboardSummary['findings'][number] | null>(null);
  const [queuedPatches, setQueuedPatches] = useState<string[]>([]);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    try {
      const response = await fetch(`${apiBaseUrl}/dashboard/summary`, { signal });
      const payload = await response.json() as ApiEnvelope;
      if (!response.ok || !payload.success || !payload.data || payload.data.mode !== 'simulated') {
        throw new Error('Dashboard preview is not available.');
      }
      setDashboard(payload.data);
      setLastUpdated(new Date(payload.data.generatedAt));
      setLoadState('ready');
    } catch {
      if (!signal?.aborted) setLoadState('unavailable');
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal);
    const timer = window.setInterval(() => void refresh(controller.signal), 15_000);
    return () => {
      window.clearInterval(timer);
      controller.abort();
    };
  }, [refresh]);

  useEffect(() => {
    const syncSection = () => setActiveSection(window.location.hash.slice(1) || 'overview');
    window.addEventListener('hashchange', syncSection);
    return () => window.removeEventListener('hashchange', syncSection);
  }, []);

  const filteredFleet = useMemo(() => dashboard?.fleet.filter((host) => {
    const term = search.trim().toLowerCase();
    const matchesSearch = !term || `${host.hostname} ${host.address} ${host.distribution} ${host.environment}`.toLowerCase().includes(term);
    return matchesSearch && (hostFilter === 'all' || host.state === hostFilter);
  }) ?? [], [dashboard, hostFilter, search]);

  const filteredFindings = useMemo(() => dashboard?.findings.filter((finding) => severityFilter === 'all' || finding.severity === severityFilter) ?? [], [dashboard, severityFilter]);
  const observedEventTotal = dashboard?.trend.reduce((total, point) => total + point.observed, 0) ?? 0;

  const queuePatchForReview = (patchId: string) => {
    setQueuedPatches((current) => current.includes(patchId) ? current : [...current, patchId]);
    setSelectedPatch(null);
  };

  return (
    <div className="app-frame">
        <aside className="sidebar">
          <a className="brand" href="#overview" aria-label="SecureWatch home">
            <span className="brand-mark"><BrandGlyph /></span>
            <span className="brand-name">secure<span>watch</span></span>
          </a>

          <div className="workspace-switcher">
            <span className="workspace-icon">N</span>
            <span className="workspace-copy"><strong>Northstar Labs</strong><small>Security workspace</small></span>
            <span className="switch-caret">⌄</span>
          </div>

          <div className="sidebar-label">WORKSPACE</div>
          <nav className="side-nav" aria-label="Main navigation">
            {navItems.map((item) => (
              <a key={item.id} className={`nav-link ${activeSection === item.id ? 'active' : ''}`} href={`#${item.id}`}>
                <span className="nav-icon" aria-hidden="true">{item.icon}</span>
                <span>{item.label}</span>
                {item.count && <span className="nav-count">{item.count}</span>}
              </a>
            ))}
          </nav>

          <div className="sidebar-label tools-label">OPERATIONS</div>
          <div className="side-nav">
            <a className="nav-link muted-link" href="#fleet"><span className="nav-icon">⌘</span><span>Collectors</span></a>
            <a className="nav-link muted-link" href="#patches"><span className="nav-icon">◷</span><span>Maintenance windows</span></a>
          </div>

          <div className="sidebar-spacer" />
          <div className="collector-card">
            <div className="collector-card-head"><span className="collector-pulse" /> PREVIEW MODE</div>
            <strong>No live collectors</strong>
            <p>System and network signals shown here are simulated.</p>
            <span className="collector-progress"><i /></span>
            <small>0 connected · 24 sample hosts</small>
          </div>
          <button className="profile-button" type="button" aria-label="Operator profile">
            <span className="avatar">SA</span><span className="profile-copy"><strong>Security analyst</strong><small>Local preview</small></span><span className="more-dots">•••</span>
          </button>
        </aside>

        <main className="main-content" id="overview">
          <header className="topbar">
            <div className="breadcrumbs"><span>Workspace</span><span>/</span><strong>Overview</strong></div>
            <div className="topbar-actions">
              <span className="demo-badge"><i /> SIMULATED DATA</span>
              <button className="icon-button" type="button" aria-label="Notifications"><BellIcon /><i className="notification-dot" /></button>
              <span className="topbar-divider" />
              <span className="topbar-date">{new Date().toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' }).toUpperCase()}</span>
            </div>
          </header>

          {loadState === 'unavailable' && (
            <div className="connection-banner" role="alert">
              <span className="banner-icon">!</span>
              <div><strong>Dashboard API unavailable</strong><span>Start the API with demo mode enabled to load the synthetic Linux fleet and detection data.</span></div>
              <button type="button" onClick={() => void refresh()}>Retry</button>
            </div>
          )}

          <section className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> SECURITY OPERATIONS <span className="eyebrow-separator">/</span> OVERVIEW</div>
              <h1>Good morning, Analyst <span className="heading-spark">✳</span></h1>
              <p>Linux fleet health, authentication activity, patch exposure, and endpoint alerts.</p>
            </div>
            <div className="heading-controls">
              <div className="refresh-time"><span className={`refresh-indicator ${loadState}`} />
                {lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : 'Connecting to API'}
              </div>
              <button className="refresh-button" type="button" onClick={() => void refresh()} aria-label="Refresh dashboard"><RefreshIcon /><span>Refresh</span></button>
            </div>
          </section>

          <section className="metric-grid" aria-label="Fleet and security summary">
            <MetricCard title="MANAGED HOSTS" value={dashboard?.metrics.managedHosts ?? '—'} icon="▣" tone="green" foot={<><span className="trend-up">↗ 2</span> added this month</>} />
            <MetricCard title="NEED ATTENTION" value={dashboard?.metrics.hostsNeedingAttention ?? '—'} icon="◉" tone="amber" foot={<><span className="trend-warn">●</span> 2 critical · 4 elevated</>} />
            <MetricCard title="SECURITY UPDATES" value={dashboard?.metrics.securityUpdates ?? '—'} icon="⬆" tone="violet" foot={<><span className="trend-muted">{dashboard?.metrics.pendingUpdates ?? '—'} total</span> package updates pending</>} />
            <MetricCard title="ENDPOINT SIEM ALERTS" value={dashboard?.metrics.networkDetections ?? '—'} icon="⌁" tone="red" foot={<><span className="trend-danger">{dashboard?.metrics.criticalDetections ?? '—'} critical</span> need analyst review</>} />
          </section>

          <section className="overview-grid">
            <article className="panel activity-panel">
              <div className="panel-header chart-header">
                <div><div className="panel-kicker">HOST & NETWORK TELEMETRY</div><h2>Endpoint activity & detections</h2><p className="panel-subtitle">Observed host signals and rule matches over 24 hours</p></div>
                <div className="chart-controls"><span className="legend-chip"><i className="legend-event" /> Observed events</span><span className="legend-chip"><i className="legend-detection" /> Detections</span><span className="period-select">Last 24h</span></div>
              </div>
              <div className="chart-wrap">
                {dashboard ? <Suspense fallback={<div className="chart-loading">Loading chart…</div>}><DashboardActivityChart trend={dashboard.trend} /></Suspense> : <div className="chart-loading">Waiting for telemetry preview…</div>}
              </div>
              <div className="chart-summary"><span><b>{dashboard ? observedEventTotal.toLocaleString() : '—'}</b> observed events</span><span><b className="summary-detections">{dashboard?.metrics.networkDetections ?? '—'}</b> detections</span><span className="chart-note"><span className="tiny-info">i</span> Sample data only</span></div>
            </article>

            <article className="panel detections-panel" id="detections">
              <div className="panel-header detection-heading">
                <div><div className="panel-kicker">NEEDS REVIEW <span className="live-count">{dashboard?.findings.length ?? '—'}</span></div><h2>Endpoint SIEM alerts</h2></div>
                <button className="text-button" type="button" onClick={() => document.getElementById('detection-list')?.scrollIntoView({ behavior: 'smooth' })}>View all <span>↗</span></button>
              </div>
              <div className="mini-detection-list">
                {(dashboard?.findings.slice(0, 3) ?? []).map((finding) => <DetectionRow key={finding.id} finding={finding} compact onAnalyze={setSelectedFinding} />)}
                {!dashboard && <div className="panel-placeholder">Detection signals will load from the API.</div>}
              </div>
              <div className="panel-bottom-link"><a href="#detection-list">Open detection queue <span>→</span></a><span className="signal-note"><i /> SIMULATION</span></div>
            </article>
          </section>

          <section className="panel fleet-panel" id="fleet">
            <div className="panel-header fleet-header">
              <div><div className="panel-kicker">LINUX ESTATE <span className="asset-count">{dashboard?.metrics.managedHosts ?? '—'} HOSTS</span></div><h2>Fleet health</h2><p className="panel-subtitle">Resource health, operating system, and patch posture</p></div>
              <div className="fleet-controls"><label className="search-box"><SearchIcon /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search hosts" aria-label="Search Linux hosts" /></label><label className="filter-button"><FilterIcon /><select value={hostFilter} onChange={(event) => setHostFilter(event.target.value as 'all' | HostState)} aria-label="Filter hosts by health"><option value="all">All health</option><option value="healthy">Healthy</option><option value="attention">Attention</option><option value="critical">Critical</option></select></label><button className="table-menu" type="button" aria-label="More fleet options">•••</button></div>
            </div>
            <div className="table-scroll"><table className="fleet-table">
              <thead><tr><th>HOST / ADDRESS</th><th>OPERATING SYSTEM</th><th>HEALTH</th><th>CPU</th><th>MEMORY</th><th>DISK</th><th>UPDATES</th><th>LAST SEEN</th></tr></thead>
              <tbody>
                {filteredFleet.map((host) => <tr key={host.id}>
                  <td><div className="host-cell"><span className="linux-mark">⌂</span><span><strong>{host.hostname}</strong><small>{host.address} <i>·</i> {host.environment}</small></span></div></td>
                  <td><div className="os-cell"><strong>{host.distribution}</strong><small>{host.release}</small></div></td>
                  <td><span className={`health-pill ${host.state}`}><i />{host.state === 'healthy' ? 'Healthy' : host.state === 'attention' ? 'Attention' : 'Critical'}</span></td>
                  <td><ResourceValue value={host.cpuPercent} /></td><td><ResourceValue value={host.memoryPercent} /></td><td><ResourceValue value={host.diskPercent} /></td>
                  <td><span className={`updates-number ${host.securityUpdates ? 'has-security' : ''}`}>{host.pendingUpdates} <small>{host.securityUpdates ? `· ${host.securityUpdates} sec` : 'pending'}</small></span></td>
                  <td className="last-seen">{relativeTime(host.lastSeen)}</td>
                </tr>)}
                {filteredFleet.length === 0 && <tr><td className="empty-table" colSpan={8}>No hosts match “{search}”.</td></tr>}
                {!dashboard && <tr><td className="empty-table" colSpan={8}>Waiting for simulated fleet data…</td></tr>}
              </tbody>
            </table></div>
            <div className="table-footer"><span>Showing <strong>{filteredFleet.length}</strong> of {dashboard?.metrics.managedHosts ?? '—'} sample hosts</span><a href="#fleet">Fleet inventory <span>→</span></a></div>
          </section>

          <section className="bottom-grid">
            <article className="panel findings-panel" id="detection-list">
              <div className="panel-header findings-header">
                <div><div className="panel-kicker">HOST & NETWORK SIGNALS</div><h2>Endpoint alert queue</h2></div>
                <label className="select-wrap"><span className="sr-only">Filter detections by severity</span><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as 'all' | Severity)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><span>⌄</span></label>
              </div>
              <div className="full-detection-list">
                {filteredFindings.map((finding) => <DetectionRow key={finding.id} finding={finding} onAnalyze={setSelectedFinding} />)}
                {filteredFindings.length === 0 && dashboard && <div className="panel-placeholder">No findings match this severity filter.</div>}
                {!dashboard && <div className="panel-placeholder">No live detections. Enable demo mode to preview sample signals.</div>}
              </div>
              <div className="panel-bottom-link"><span className="disclaimer-inline">SSH failure bursts, host-level success co-occurrence, and sudo volume are reviewed as signals.</span><span className="signal-note"><i /> SIMULATION</span></div>
            </article>

            <article className="panel patch-panel" id="patches">
              <div className="panel-header patch-heading">
                <div><div className="panel-kicker">MAINTENANCE PLANNING <span className="patch-count">{dashboard?.metrics.securityUpdates ?? '—'} SECURITY</span></div><h2>Patch recommendations</h2><p className="panel-subtitle">Review available security updates for Linux hosts</p></div>
                <span className="patch-shield"><ShieldIcon /></span>
              </div>
              <div className="patch-list">
                {(dashboard?.patches ?? []).map((patch) => <button className="patch-row" type="button" key={patch.id} onClick={() => setSelectedPatch(patch)}>
                  <span className={`patch-priority ${patch.severity}`}><PackageIcon /></span>
                  <span className="patch-row-copy"><strong>{patch.packageName}</strong><small>{patch.host} <i>·</i> {patch.advisory}</small></span>
                  <span className={`severity-label ${patch.severity}`}>{patch.severity}</span>
                  <span className="patch-chevron">›</span>
                </button>)}
                {!dashboard && <div className="panel-placeholder">Patch recommendations will load from the API.</div>}
              </div>
              <div className="patch-footer"><span><span className="tiny-info">i</span> Recommendations only — no system changes run.</span><button className="text-button" type="button" onClick={() => dashboard?.patches[0] && setSelectedPatch(dashboard.patches[0])}>Review queue <span>→</span></button></div>
            </article>
          </section>

          <Suspense fallback={<div className="admin-loading admin-lazy-loading">Loading admin operations…</div>}>
            <AdminOperationsPanel patches={dashboard?.patches ?? []} />
          </Suspense>

          <footer className="app-footer"><span>SECUREWATCH <i>/</i> SECURITY OPERATIONS</span><span><span className="footer-lock">▣</span> LOCAL DEMO ENVIRONMENT <i>·</i> NO LIVE SYSTEMS CONNECTED</span></footer>
        </main>

        <Suspense fallback={null}><PatchReviewDialog selectedPatch={selectedPatch} inReviewQueue={Boolean(selectedPatch && queuedPatches.includes(selectedPatch.id))} onClose={() => setSelectedPatch(null)} onAddToReview={() => selectedPatch && queuePatchForReview(selectedPatch.id)} /></Suspense>
        <Suspense fallback={null}><SocCopilotDialog finding={selectedFinding} onClose={() => setSelectedFinding(null)} /></Suspense>
    </div>
  );
}

function MetricCard({ title, value, icon, tone, foot }: { title: string; value: string | number; icon: string; tone: string; foot: ReactNode }) {
  return <article className="metric-card"><div className="metric-top"><span>{title}</span><span className={`metric-icon ${tone}`}>{icon}</span></div><div className="metric-value">{value}</div><div className="metric-foot">{foot}</div><span className={`metric-accent ${tone}`} /></article>;
}

function ResourceValue({ value }: { value: number }) {
  const tone = value >= 85 ? 'danger' : value >= 70 ? 'warn' : 'normal';
  return <span className="resource-cell"><span className={`resource-bar ${tone}`}><i style={{ width: `${value}%` }} /></span><small className={tone}>{value}%</small></span>;
}

function DetectionRow({ finding, compact = false, onAnalyze }: { finding: DashboardSummary['findings'][number]; compact?: boolean; onAnalyze: (finding: DashboardSummary['findings'][number]) => void }) {
  return <div className={`detection-row ${compact ? 'compact' : ''}`}>
    <span className={`severity-mark ${finding.severity}`}><i /></span>
    <div className="detection-main"><div className="detection-title-row"><strong>{finding.title}</strong><span className={`severity-label ${finding.severity}`}>{finding.severity}</span></div>
      <p>{finding.description}</p>
      <div className="detection-meta"><span><span className="meta-icon">⌘</span>{finding.host}</span><span><span className="meta-icon">⇢</span>{finding.source}</span><span>{relativeTime(finding.observedAt)}</span></div>
    </div>
    <div className="detection-actions"><button type="button" className="ai-triage-button" onClick={() => onAnalyze(finding)} aria-label={`Analyze ${finding.title} with AI`}><span>✳</span><span>AI triage</span></button>{!compact && <button type="button" className="row-more" aria-label={`More options for ${finding.title}`}>•••</button>}</div>
  </div>;
}

function relativeTime(value: string) {
  const minutes = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 60_000));
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.floor(minutes / 60)}h ago`;
}

function BrandGlyph() { return <svg viewBox="0 0 28 28" aria-hidden="true"><path d="M14 3.5 23 7v7.2c0 5.1-3.5 8.8-9 10.4-5.5-1.6-9-5.3-9-10.4V7l9-3.5Z" /><path d="m9.2 14 3.1 3.1 6.6-7" /></svg>; }
function BellIcon() { return <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M15.5 8.2a5.5 5.5 0 0 0-11 0c0 6.3-2 6.3-2 7.3h15c0-1-2-1-2-7.3ZM8 18h4" /></svg>; }
function RefreshIcon() { return <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M16.6 8.1A6.8 6.8 0 0 0 4.4 5.6L3 7M3 3.6V7h3.4M3.4 11.9a6.8 6.8 0 0 0 12.2 2.5L17 13M17 16.4V13h-3.4" /></svg>; }
function SearchIcon() { return <svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="8.8" cy="8.8" r="5.7" /><path d="m13 13 4 4" /></svg>; }
function FilterIcon() { return <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5h14M5.5 10h9M8 15h4" /></svg>; }
function ShieldIcon() { return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 3 8 3v6.4c0 4.4-3.1 7.4-8 8.9-4.9-1.5-8-4.5-8-8.9V6l8-3Z" /><path d="m8.5 12 2.2 2.2 4.8-5" /></svg>; }
function PackageIcon() { return <svg viewBox="0 0 20 20" aria-hidden="true"><path d="m10 2.5 7 3.8v7.4l-7 3.8-7-3.8V6.3l7-3.8Z" /><path d="m3.2 6.4 6.8 3.8 6.8-3.8M10 10.3v7" /></svg>; }
