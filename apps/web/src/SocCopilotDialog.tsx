import { useEffect, useRef, useState } from 'react';
import { Dialog, DialogContent, DialogTitle } from '@mui/material';

type Finding = {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  source: string;
  destination: string;
  host: string;
  detector: string;
  observedAt: string;
  state: 'new' | 'investigating' | 'reviewed';
};

type Analysis = {
  assessment: 'likely_malicious' | 'suspicious' | 'inconclusive' | 'likely_benign';
  priority: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  summary: string;
  supportingSignals: string[];
  analystChecks: string[];
  containmentGuidance: string;
};

type ApiEnvelope = {
  success: boolean;
  data?: Analysis;
  error?: { code?: string; message?: string };
};

type LoadState = 'idle' | 'loading' | 'ready' | 'error';

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:4000/api/v1';

export default function SocCopilotDialog({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const [loadState, setLoadState] = useState<LoadState>('idle');
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const controllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    controllerRef.current?.abort();
    setLoadState('idle');
    setAnalysis(null);
    setError(null);
    return () => controllerRef.current?.abort();
  }, [finding?.id]);

  const analyze = async () => {
    if (!finding) return;
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setLoadState('loading');
    setAnalysis(null);
    setError(null);

    try {
      const response = await fetch(`${apiBaseUrl}/copilot/analyze`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ findingId: finding.id }),
        signal: controller.signal,
      });
      const payload = await response.json() as ApiEnvelope;
      if (!response.ok || !payload.success || !payload.data) {
        const message = payload.error?.code === 'AI_NOT_CONFIGURED'
          ? 'Add OPENAI_API_KEY to the API environment and restart the API to enable AI triage.'
          : payload.error?.message ?? 'The analysis could not be completed. Try again.';
        throw new Error(message);
      }
      setAnalysis(payload.data);
      setLoadState('ready');
    } catch (caught) {
      if (controller.signal.aborted) return;
      setError(caught instanceof Error ? caught.message : 'The analysis could not be completed. Try again.');
      setLoadState('error');
    }
  };

  return <Dialog open={Boolean(finding)} onClose={onClose} maxWidth="md" fullWidth slotProps={{ paper: { className: 'copilot-dialog-paper' } }}>
    {finding && <>
      <DialogTitle className="dialog-title copilot-dialog-title">
        <div><span className="dialog-kicker">SECUREWATCH AI · SIMULATED ALERT</span><h2>AI incident triage</h2></div>
        <button type="button" className="dialog-close" onClick={onClose} aria-label="Close AI incident triage">×</button>
      </DialogTitle>
      <DialogContent className="dialog-content copilot-dialog-content">
        <div className="copilot-finding">
          <div className="copilot-finding-heading"><span className={`severity-mark ${finding.severity}`}><i /></span><div><div className="detection-title-row"><strong>{finding.title}</strong><span className={`severity-label ${finding.severity}`}>{finding.severity}</span></div><p>{finding.description}</p></div></div>
          <div className="copilot-finding-meta"><span>HOST <b>{finding.host}</b></span><span>SOURCE <b>{finding.source}</b></span><span>DESTINATION <b>{finding.destination}</b></span><span>DETECTOR <b>{finding.detector}</b></span></div>
        </div>

        {loadState === 'idle' && <div className="copilot-empty"><span className="copilot-spark">✳</span><strong>Ask AI to assess this signal</strong><p>The model will summarize the evidence and suggest analyst checks. It cannot access a host or take action.</p></div>}
        {loadState === 'loading' && <div className="copilot-loading" role="status"><span className="copilot-loader" /><div><strong>Reviewing alert evidence</strong><span>This can take a few seconds.</span></div></div>}
        {loadState === 'error' && <div className="copilot-error" role="alert"><strong>AI analysis unavailable</strong><span>{error}</span></div>}
        {analysis && <div className="copilot-analysis">
          <div className="copilot-assessment"><span className={`assessment-pill ${analysis.assessment}`}><i />{analysis.assessment.replaceAll('_', ' ')}</span><span className={`severity-label ${analysis.priority}`}>Priority · {analysis.priority}</span><span className="copilot-confidence">Confidence <b>{analysis.confidence}%</b></span></div>
          <div className="copilot-summary"><span className="copilot-section-label">ASSESSMENT</span><p>{analysis.summary}</p></div>
          <div className="copilot-analysis-grid">
            <section><span className="copilot-section-label">SUPPORTING SIGNALS</span><ul>{analysis.supportingSignals.map((signal, index) => <li key={`${index}-${signal}`}>{signal}</li>)}</ul></section>
            <section><span className="copilot-section-label">ANALYST CHECKS</span><ul>{analysis.analystChecks.map((check, index) => <li key={`${index}-${check}`}>{check}</li>)}</ul></section>
          </div>
          <div className="copilot-guidance"><span className="copilot-section-label">CONTAINMENT GUIDANCE</span><p>{analysis.containmentGuidance}</p></div>
        </div>}

        <div className="copilot-disclaimer"><span className="tiny-info">i</span><span>AI output is advisory and may be wrong. Validate it against trusted telemetry. Any containment requires an authorized analyst; this preview performs no host actions.</span></div>
        <div className="dialog-actions"><button className="dialog-secondary" type="button" onClick={onClose}>Close</button><button className="dialog-primary copilot-run-button" type="button" onClick={() => void analyze()} disabled={loadState === 'loading'}><span>✳</span>{loadState === 'ready' ? 'Analyze again' : loadState === 'loading' ? 'Analyzing…' : 'Analyze alert'}</button></div>
      </DialogContent>
    </>}
  </Dialog>;
}
