import type { DashboardSummary } from './demo-dashboard.types.js';

const minutesAgo = (minutes: number, now: Date): string => new Date(now.getTime() - minutes * 60_000).toISOString();

export function getDemoDashboard(now = new Date()): DashboardSummary {
  const trend = Array.from({ length: 12 }, (_, index) => {
    const hour = new Date(now.getTime() - (11 - index) * 2 * 60 * 60_000);
    return {
      time: hour.toISOString(),
      observed: [122, 148, 131, 179, 165, 214, 188, 232, 206, 245, 219, 261][index] ?? 120,
      detections: [3, 5, 2, 7, 4, 9, 6, 12, 7, 14, 8, 11][index] ?? 2,
    };
  });

  return {
    mode: 'simulated',
    generatedAt: now.toISOString(),
    metrics: {
      managedHosts: 24,
      hostsNeedingAttention: 6,
      pendingUpdates: 31,
      securityUpdates: 7,
      networkDetections: 12,
      criticalDetections: 2,
    },
    trend,
    fleet: [
      { id: 'host-01', hostname: 'edge-gw-01', address: '10.20.1.11', distribution: 'Ubuntu Server', release: '24.04 LTS', environment: 'PRODUCTION', state: 'healthy', cpuPercent: 32, memoryPercent: 58, diskPercent: 46, pendingUpdates: 2, securityUpdates: 0, lastSeen: minutesAgo(1, now) },
      { id: 'host-02', hostname: 'api-node-03', address: '10.20.4.23', distribution: 'Ubuntu Server', release: '22.04 LTS', environment: 'PRODUCTION', state: 'attention', cpuPercent: 76, memoryPercent: 81, diskPercent: 68, pendingUpdates: 8, securityUpdates: 3, lastSeen: minutesAgo(2, now) },
      { id: 'host-03', hostname: 'payments-db-02', address: '10.20.5.18', distribution: 'Debian', release: '12.8', environment: 'PRODUCTION', state: 'critical', cpuPercent: 91, memoryPercent: 87, diskPercent: 84, pendingUpdates: 5, securityUpdates: 2, lastSeen: minutesAgo(1, now) },
      { id: 'host-04', hostname: 'worker-batch-07', address: '10.20.6.47', distribution: 'Ubuntu Server', release: '24.04 LTS', environment: 'STAGING', state: 'healthy', cpuPercent: 49, memoryPercent: 62, diskPercent: 54, pendingUpdates: 1, securityUpdates: 0, lastSeen: minutesAgo(3, now) },
      { id: 'host-05', hostname: 'vpn-gateway-01', address: '10.20.1.5', distribution: 'Ubuntu Server', release: '22.04 LTS', environment: 'PRODUCTION', state: 'attention', cpuPercent: 63, memoryPercent: 73, diskPercent: 72, pendingUpdates: 6, securityUpdates: 1, lastSeen: minutesAgo(4, now) },
      { id: 'host-06', hostname: 'auth-service-02', address: '10.20.3.12', distribution: 'Debian', release: '12.8', environment: 'PRODUCTION', state: 'healthy', cpuPercent: 27, memoryPercent: 43, diskPercent: 38, pendingUpdates: 3, securityUpdates: 0, lastSeen: minutesAgo(2, now) },
    ],
    findings: [
      { id: 'det-1042', severity: 'critical', title: 'Repeated SSH authentication failures', description: '31 failed attempts against a privileged account within 4 minutes.', source: '198.51.100.42', destination: '10.20.4.23:22', host: 'api-node-03', detector: 'Linux auth burst', observedAt: minutesAgo(3, now), state: 'new' },
      { id: 'det-1041', severity: 'high', title: 'Unusual outbound DNS pattern', description: 'Periodic DNS requests differ from this host’s 7-day baseline.', source: '10.20.5.18', destination: '203.0.113.53:53', host: 'payments-db-02', detector: 'DNS behavior', observedAt: minutesAgo(11, now), state: 'investigating' },
      { id: 'det-1040', severity: 'high', title: 'Port-scan indicator observed', description: 'Connection attempts touched 18 destination ports in a short window.', source: '192.0.2.87', destination: '10.20.1.11', host: 'edge-gw-01', detector: 'Network sweep heuristic', observedAt: minutesAgo(24, now), state: 'new' },
      { id: 'det-1039', severity: 'medium', title: 'New external service destination', description: 'A workload contacted an address not seen in the prior 30 days.', source: '10.20.6.47', destination: '203.0.113.81:443', host: 'worker-batch-07', detector: 'Destination novelty', observedAt: minutesAgo(41, now), state: 'reviewed' },
    ],
    patches: [
      { id: 'patch-2024-01', host: 'payments-db-02', packageName: 'openssl', currentVersion: '3.0.13-0ubuntu3.4', candidateVersion: '3.0.13-0ubuntu3.6', advisory: 'USN-7421-1', severity: 'critical', rebootRequired: false, recommendation: 'Review package changelog and schedule an approved maintenance window.' },
      { id: 'patch-2024-02', host: 'api-node-03', packageName: 'linux-image-generic', currentVersion: '6.8.0.52.53', candidateVersion: '6.8.0.55.56', advisory: 'USN-7414-2', severity: 'high', rebootRequired: true, recommendation: 'Coordinate kernel update with service owner; reboot is required.' },
      { id: 'patch-2024-03', host: 'vpn-gateway-01', packageName: 'openssh-server', currentVersion: '1:8.9p1-3ubuntu0.10', candidateVersion: '1:8.9p1-3ubuntu0.11', advisory: 'USN-7402-1', severity: 'high', rebootRequired: false, recommendation: 'Review access impact and roll out through the normal change process.' },
    ],
  };
}
