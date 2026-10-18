import { Dialog, DialogContent, DialogTitle } from '@mui/material';

type PatchRecommendation = {
  id: string;
  host: string;
  packageName: string;
  currentVersion: string;
  candidateVersion: string;
  advisory: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  rebootRequired: boolean;
  recommendation: string;
};

export default function PatchReviewDialog({
  selectedPatch,
  inReviewQueue,
  onClose,
  onAddToReview,
}: {
  selectedPatch: PatchRecommendation | null;
  inReviewQueue: boolean;
  onClose: () => void;
  onAddToReview: () => void;
}) {
  return <Dialog open={Boolean(selectedPatch)} onClose={onClose} maxWidth="sm" fullWidth slotProps={{ paper: { className: 'patch-dialog-paper' } }}>
    {selectedPatch && <>
      <DialogTitle className="dialog-title"><div><span className="dialog-kicker">PATCH RECOMMENDATION · {selectedPatch.advisory}</span><h2>Review package update</h2></div><button type="button" className="dialog-close" onClick={onClose} aria-label="Close">×</button></DialogTitle>
      <DialogContent className="dialog-content">
        <div className="dialog-package"><span className={`patch-priority ${selectedPatch.severity}`}><PackageIcon /></span><span><strong>{selectedPatch.packageName}</strong><small>{selectedPatch.host}</small></span><span className={`severity-label ${selectedPatch.severity}`}>{selectedPatch.severity}</span></div>
        <div className="version-comparison"><div><small>INSTALLED VERSION</small><code>{selectedPatch.currentVersion}</code></div><span>→</span><div><small>AVAILABLE VERSION</small><code>{selectedPatch.candidateVersion}</code></div></div>
        <div className="recommendation-box"><span className="tiny-info">i</span><p>{selectedPatch.recommendation}</p></div>
        <div className="maintenance-note"><strong>{selectedPatch.rebootRequired ? 'Reboot required' : 'No reboot indicated'}</strong><span>This preview does not connect to apt, run commands, or change a host. Any update requires an authorized operator and an approved maintenance window.</span></div>
        <div className="dialog-actions"><button className="dialog-secondary" type="button" onClick={onClose}>Close</button><button className="dialog-primary" type="button" onClick={onAddToReview}>{inReviewQueue ? 'In review queue' : 'Add to review queue'}</button></div>
      </DialogContent>
    </>}
  </Dialog>;
}

function PackageIcon() { return <svg viewBox="0 0 20 20" aria-hidden="true"><path d="m10 2.5 7 3.8v7.4l-7 3.8-7-3.8V6.3l7-3.8Z" /><path d="m3.2 6.4 6.8 3.8 6.8-3.8M10 10.3v7" /></svg>; }
