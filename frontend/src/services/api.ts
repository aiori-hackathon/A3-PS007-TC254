export interface HealthData {
  status: string;
  app: string;
  version: string;
  mode: string;
  config_loaded: boolean;
  timestamp: string;
}

export interface LabStatusData {
  bridge_name: string;
  bridge_status: string;
  is_active: boolean;
  is_healthy: boolean;
  manifest_recorded: boolean;
  monitor_running: boolean;
  namespaces: string[];
  devices: Record<string, any>;
  router: Record<string, any>;
  attacker: Record<string, any>;
}

export interface DeviceData {
  id: string;
  name: string;
  device_type: string;
  namespace: string;
  tenant_id: string;
  current_ipv6: string;
  current_pseudonym: string;
  rotation_count: number;
  last_rotation: string | null;
  session_expires_at: string | null;
  session_ttl_remaining: number;
  is_active: boolean;
}

export interface SessionData {
  session_id_masked: string;
  device_id: string;
  tenant_id: string;
  current_pseudonym: string;
  created_at: string;
  expires_at: string;
  ttl_remaining_seconds: number;
  is_valid: boolean;
}

export interface SecurityEventData {
  id: string;
  tenant_id: string;
  timestamp: string;
  event_type: string;
  severity: string;
  source_ip: string;
  target_ip: string | null;
  affected_pseudonym: string | null;
  details: Record<string, any>;
  verified: boolean;
  remediation_status: string;
}

export interface NormalizedAlertData {
  alert_id: string;
  timestamp: string;
  alert_type: string;
  severity: string;
  rule_id: string;
  reason: string;
  interface: string;
  evidence: Record<string, any>;
  experiment_id: string | null;
  status: string;
  tenant_scope: string | null;
}

export interface ExperimentData {
  experiment_id: string;
  scenario_type: string;
  target_namespaces: string[];
  parameters: Record<string, any>;
  status: string;
  start_time: string;
  completion_time: string | null;
  packets_sent: number;
  alerts_triggered: number;
}

export interface MetricsData {
  timestamp: string;
  detection_metrics: {
    true_positives: number;
    false_positives: number;
    false_negatives: number;
    true_negatives: number;
    detection_rate_pct: number;
    precision_pct?: number;
    false_alarm_rate_pct: number;
    avg_detection_latency_ms: number;
    completed_experiments_count?: number;
    has_data?: boolean;
    message?: string;
  };
  privacy_metrics: {
    active_pseudonyms: number;
    expired_pseudonyms_purged: number;
    total_rotations: number;
    authorized_session_continuity_pct: number;
    unauthorized_correlations_blocked: number;
    tracking_resistance_score: number;
  };
  traffic_rates: {
    current_pps: number;
    icmpv6_ns_rate: number;
    icmpv6_na_rate: number;
    icmpv6_ra_rate: number;
    ndp_threshold: number;
  };
}

export const api = {
  async getHealth(): Promise<HealthData> {
    const res = await fetch('/api/health');
    if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
    return res.json();
  },

  async getLabStatus(): Promise<LabStatusData> {
    const res = await fetch('/api/lab/status');
    if (!res.ok) throw new Error(`Failed to fetch lab status: ${res.statusText}`);
    return res.json();
  },

  async startLab(): Promise<any> {
    const res = await fetch('/api/lab/start', { method: 'POST' });
    if (!res.ok) throw new Error('Failed to start lab');
    return res.json();
  },

  async stopLab(): Promise<any> {
    const res = await fetch('/api/lab/stop', { method: 'POST' });
    if (!res.ok) throw new Error('Failed to stop lab');
    return res.json();
  },

  async getDevices(tenantId: string = 'tenant-alpha'): Promise<DeviceData[]> {
    const res = await fetch('/api/devices', {
      headers: { 'X-Tenant-ID': tenantId },
    });
    if (!res.ok) throw new Error(`Failed to fetch devices: ${res.statusText}`);
    return res.json();
  },

  async rotateDevice(deviceId: string, tenantId: string = 'tenant-alpha'): Promise<any> {
    const res = await fetch(`/api/devices/${deviceId}/rotate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': tenantId,
      },
      body: JSON.stringify({}),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || 'Rotation failed');
    }
    return res.json();
  },

  async getSessions(tenantId: string = 'tenant-alpha'): Promise<SessionData[]> {
    const res = await fetch('/api/sessions', {
      headers: { 'X-Tenant-ID': tenantId },
    });
    if (!res.ok) throw new Error(`Failed to fetch sessions: ${res.statusText}`);
    return res.json();
  },

  async getEvents(tenantId: string = 'tenant-alpha', limit: number = 50): Promise<SecurityEventData[]> {
    const res = await fetch(`/api/events?limit=${limit}`, {
      headers: { 'X-Tenant-ID': tenantId },
    });
    if (!res.ok) throw new Error(`Failed to fetch events: ${res.statusText}`);
    return res.json();
  },

  async getAlerts(tenantId: string = 'tenant-alpha', alertType?: string): Promise<NormalizedAlertData[]> {
    const url = alertType ? `/api/alerts?alert_type=${alertType}` : '/api/alerts';
    const res = await fetch(url, {
      headers: { 'X-Tenant-ID': tenantId },
    });
    if (!res.ok) throw new Error(`Failed to fetch alerts: ${res.statusText}`);
    return res.json();
  },

  async getExperiments(): Promise<ExperimentData[]> {
    const res = await fetch('/api/experiments');
    if (!res.ok) throw new Error(`Failed to fetch experiments: ${res.statusText}`);
    return res.json();
  },

  async startNormalExperiment(durationSeconds: number = 2, intervalSec: number = 0.2): Promise<any> {
    const res = await fetch('/api/experiments/normal', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ duration_seconds: durationSeconds, packet_interval_sec: intervalSec }),
    });
    if (!res.ok) throw new Error('Failed to start normal traffic experiment');
    return res.json();
  },

  async startRogueRAExperiment(
    tenantId: string = 'tenant-alpha',
    rogueSource: string = 'fe80::dead:beef',
    unauthorizedPrefix: string = '2001:db8:baad::/64',
    routerLifetime: number = 1800
  ): Promise<any> {
    const res = await fetch('/api/experiments/rogue-ra', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': tenantId,
      },
      body: JSON.stringify({
        rogue_source: rogueSource,
        unauthorized_prefix: unauthorizedPrefix,
        router_lifetime: routerLifetime,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || 'Rogue RA experiment failed');
    }
    return res.json();
  },

  async startNDPBurstExperiment(
    tenantId: string = 'tenant-alpha',
    targetIp: string = '2001:db8:6::11',
    packetCount: number = 90,
    packetRatePps: number = 50
  ): Promise<any> {
    const res = await fetch('/api/experiments/ndp-burst', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': tenantId,
      },
      body: JSON.stringify({
        target_ip: targetIp,
        packet_count: packetCount,
        packet_rate_pps: packetRatePps,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || 'NDP burst experiment failed');
    }
    return res.json();
  },

  async stopExperiment(): Promise<any> {
    const res = await fetch('/api/experiments/stop', { method: 'POST' });
    if (!res.ok) throw new Error('Failed to stop experiment');
    return res.json();
  },

  async getMetrics(): Promise<MetricsData> {
    const res = await fetch('/api/metrics');
    if (!res.ok) throw new Error(`Failed to fetch metrics: ${res.statusText}`);
    return res.json();
  },

  async triggerRogueRA(tenantId: string = 'tenant-alpha', roguePrefix: string = '2001:db8:baad::/64'): Promise<any> {
    return this.startRogueRAExperiment(tenantId, 'fe80::dead:beef', roguePrefix, 1800);
  },

  async triggerNDPFlood(tenantId: string = 'tenant-alpha', packetCount: number = 90): Promise<any> {
    return this.startNDPBurstExperiment(tenantId, '2001:db8:6::11', packetCount, 50);
  },

  async stopAttacks(): Promise<any> {
    return this.stopExperiment();
  },
};
