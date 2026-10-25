import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from '../App';
import { api } from '../services/api';

vi.mock('../services/api', () => ({
  api: {
    getHealth: vi.fn(),
    getLabStatus: vi.fn(),
    getDevices: vi.fn(),
    getSessions: vi.fn(),
    getEvents: vi.fn(),
    getAlerts: vi.fn(),
    getExperiments: vi.fn(),
    getMetrics: vi.fn(),
    startNormalExperiment: vi.fn(),
    startRogueRaExperiment: vi.fn(),
    startNdpBurstExperiment: vi.fn(),
    stopExperiment: vi.fn(),
    rotateDevice: vi.fn(),
  },
}));

describe('Priv6Guard Professional Cybersecurity Dashboard', () => {
  const mockHealth = {
    status: 'healthy',
    app: 'PRIV6GUARD',
    version: '1.0.0',
    mode: 'LAB_SIMULATION',
    config_loaded: true,
    timestamp: '2026-10-25T12:00:00Z',
  };

  const mockLabStatus = {
    bridge_name: 'p6g-br0',
    bridge_status: 'UP',
    is_active: true,
    is_healthy: true,
    manifest_recorded: true,
    monitor_running: true,
    namespaces: ['p6g-iot1', 'p6g-iot2', 'p6g-iot3'],
    devices: {},
    router: { exists: true, state: 'UP' },
    attacker: { exists: true, state: 'UP' },
  };

  const mockDevices = [
    {
      id: 'p6g-iot1',
      name: 'smart_thermostat',
      device_type: 'thermostat',
      namespace: 'p6g-ns-iot1',
      tenant_id: 'tenant-alpha',
      current_ipv6: '2001:db8:6::11',
      current_pseudonym: 'p6g-ps-12345678abcdef',
      rotation_count: 2,
      last_rotation: '2026-10-25T12:00:00Z',
      session_expires_at: '2026-10-25T12:05:00Z',
      session_ttl_remaining: 240,
      is_active: true,
    },
  ];

  const mockAlerts = [
    {
      alert_id: 'alt-ra-001',
      timestamp: '2026-10-25T12:01:00Z',
      alert_type: 'ROGUE_RA_POLICY_VIOLATION',
      severity: 'CRITICAL',
      rule_id: 'RULE-RA-UNAUTHORIZED-SOURCE',
      reason: 'Unauthorized router advertisement from fe80::dead:beef',
      interface: 'p6g-br0',
      evidence: { source_ip: 'fe80::dead:beef' },
      experiment_id: 'exp-ra-1',
      status: 'ACTIVE',
      tenant_scope: 'tenant-alpha',
    },
    {
      alert_id: 'alt-ndp-002',
      timestamp: '2026-10-25T12:02:00Z',
      alert_type: 'NDP_RATE_ANOMALY',
      severity: 'HIGH',
      rule_id: 'RULE-NDP-NS-RATE-LIMIT',
      reason: 'Abnormal NDP burst detected: 16.0 pps',
      interface: 'p6g-br0',
      evidence: { source_ip: '2001:db8:6::bad' },
      experiment_id: 'exp-ndp-1',
      status: 'ACTIVE',
      tenant_scope: 'tenant-alpha',
    },
  ];

  const mockMetrics = {
    timestamp: '2026-10-25T12:00:00Z',
    detection_metrics: {
      true_positives: 4,
      false_positives: 0,
      false_negatives: 0,
      true_negatives: 2,
      detection_rate_pct: 100.0,
      precision_pct: 100.0,
      false_alarm_rate_pct: 0.0,
      avg_detection_latency_ms: 35.2,
      completed_experiments_count: 6,
      has_data: true,
    },
    privacy_metrics: {
      active_pseudonyms: 3,
      expired_pseudonyms_purged: 8,
      total_rotations: 12,
      authorized_session_continuity_pct: 100.0,
      unauthorized_correlations_blocked: 15,
      tracking_resistance_score: 1.0,
    },
    traffic_rates: {
      current_pps: 14.2,
      icmpv6_ns_rate: 2.4,
      icmpv6_na_rate: 1.8,
      icmpv6_ra_rate: 0.2,
      ndp_threshold: 15.0,
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    (api.getHealth as any).mockResolvedValue(mockHealth);
    (api.getLabStatus as any).mockResolvedValue(mockLabStatus);
    (api.getDevices as any).mockResolvedValue(mockDevices);
    (api.getSessions as any).mockResolvedValue([]);
    (api.getEvents as any).mockResolvedValue([]);
    (api.getAlerts as any).mockResolvedValue(mockAlerts);
    (api.getExperiments as any).mockResolvedValue([]);
    (api.getMetrics as any).mockResolvedValue(mockMetrics);
  });

  it('renders application visual identity: title, tagline, hackathon code, team code, and lab simulation indicator', async () => {
    render(<App />);

    expect(await screen.findByText('PRIV6GUARD')).toBeInTheDocument();
    expect(screen.getAllByText(/Security without permanent tracking/i).length).toBeGreaterThan(0);
    expect(screen.getByText('AIORI HACKATHON 3 — PS-007')).toBeInTheDocument();
    expect(screen.getByText('A3-PS007-TC254')).toBeInTheDocument();
    expect(screen.getByText('LAB SIMULATION')).toBeInTheDocument();
  });

  it('renders all 8 primary navigation tabs', async () => {
    render(<App />);

    expect(await screen.findByRole('button', { name: /^Overview$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Devices$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Sessions & Privacy$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Security Alerts$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Network Activity$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Experiments$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Evaluation$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Settings & Docs$/i })).toBeInTheDocument();
  });

  it('handles backend connection status indicators accurately', async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/API: CONNECTED/i)).toBeInTheDocument();
    });
  });

  it('handles backend connection failure gracefully', async () => {
    (api.getHealth as any).mockRejectedValue(new Error('Connection refused'));
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/API: DISCONNECTED/i)).toBeInTheDocument();
    });
  });

  it('supports tenant-specific data switching between Tenant Alpha and Tenant Beta', async () => {
    render(<App />);

    const betaButton = await screen.findByRole('button', { name: /Beta/i });
    fireEvent.click(betaButton);

    await waitFor(() => {
      expect(api.getDevices).toHaveBeenCalledWith('tenant-beta');
      expect(api.getAlerts).toHaveBeenCalledWith('tenant-beta');
    });
  });

  it('filters security alerts by violation type in the Security Alerts tab', async () => {
    render(<App />);

    // Switch to Alerts tab
    const alertsTab = await screen.findByRole('button', { name: /^Security Alerts$/i });
    fireEvent.click(alertsTab);

    // Initial list has both alerts
    expect(await screen.findByText('alt-ra-001')).toBeInTheDocument();
    expect(screen.getByText('alt-ndp-002')).toBeInTheDocument();

    // Click RA Filter
    const raFilterBtn = screen.getByRole('button', { name: /^Rogue RA$/i });
    fireEvent.click(raFilterBtn);

    expect(screen.getByText('alt-ra-001')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByText('alt-ndp-002')).not.toBeInTheDocument();
    });
  });

  it('displays confirmation modal before executing controlled attack scenarios in isolated lab', async () => {
    render(<App />);

    // Switch to Experiments tab
    const expTab = await screen.findByRole('button', { name: /^Experiments$/i });
    fireEvent.click(expTab);

    // Click Rogue RA launch button
    const launchRogueBtn = await screen.findByRole('button', { name: /Launch Rogue RA/i });
    fireEvent.click(launchRogueBtn);

    // Modal must appear with explicit lab confinement warning
    expect(await screen.findByText(/Confirm Attack Simulation/i)).toBeInTheDocument();
    expect(screen.getByText(/strictly confined to the isolated Priv6Guard virtual lab/i)).toBeInTheDocument();

    // Cancel modal
    const cancelBtn = screen.getByRole('button', { name: /^Cancel$/i });
    fireEvent.click(cancelBtn);

    await waitFor(() => {
      expect(screen.queryByText(/Confirm Attack Simulation/i)).not.toBeInTheDocument();
    });
  });

  it('renders empirical evaluation metrics and sample size in the Evaluation tab', async () => {
    render(<App />);

    // Switch to Evaluation tab
    const evalTab = await screen.findByRole('button', { name: /^Evaluation$/i });
    fireEvent.click(evalTab);

    expect(await screen.findByText('TRUE POSITIVE RATE')).toBeInTheDocument();
    expect(screen.getAllByText('100%').length).toBeGreaterThan(0); // Detection Rate
    expect(screen.getByText('35.2 ms')).toBeInTheDocument();        // Latency
    expect(screen.getByText('1.00 / 1.0')).toBeInTheDocument();     // Privacy Score
  });

  it('handles empty evaluation state when no experiments have been executed', async () => {
    (api.getMetrics as any).mockResolvedValue({
      timestamp: '2026-10-25T12:00:00Z',
      detection_metrics: {
        true_positives: 0,
        false_positives: 0,
        false_negatives: 0,
        true_negatives: 0,
        detection_rate_pct: 0.0,
        precision_pct: 0.0,
        false_alarm_rate_pct: 0.0,
        avg_detection_latency_ms: 0.0,
        completed_experiments_count: 0,
        has_data: false,
        message: 'No experiments executed yet. Insufficient data to calculate measured performance.',
      },
      privacy_metrics: {
        active_pseudonyms: 0,
        expired_pseudonyms_purged: 0,
        total_rotations: 0,
        authorized_session_continuity_pct: 100.0,
        unauthorized_correlations_blocked: 0,
        tracking_resistance_score: 1.0,
      },
      traffic_rates: {
        current_pps: 0.0,
        icmpv6_ns_rate: 0.0,
        icmpv6_na_rate: 0.0,
        icmpv6_ra_rate: 0.0,
        ndp_threshold: 15.0,
      },
    });

    render(<App />);
    const evalTab = await screen.findByRole('button', { name: /^Evaluation$/i });
    fireEvent.click(evalTab);

    expect(await screen.findByText(/Insufficient evaluation data/i)).toBeInTheDocument();
  });
});
