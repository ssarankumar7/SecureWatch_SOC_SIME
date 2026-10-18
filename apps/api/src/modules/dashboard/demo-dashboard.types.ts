export type HostState = 'healthy' | 'attention' | 'critical';
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface FleetHost {
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
}

export interface NetworkFinding {
  id: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  source: string;
  destination: string;
  host: string;
  detector: string;
  observedAt: string;
  state: 'new' | 'investigating' | 'reviewed';
}

export interface PatchRecommendation {
  id: string;
  host: string;
  packageName: string;
  currentVersion: string;
  candidateVersion: string;
  advisory: string;
  severity: FindingSeverity;
  rebootRequired: boolean;
  recommendation: string;
}

export interface TrendPoint {
  time: string;
  observed: number;
  detections: number;
}

export interface DashboardSummary {
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
  trend: TrendPoint[];
  fleet: FleetHost[];
  findings: NetworkFinding[];
  patches: PatchRecommendation[];
}
