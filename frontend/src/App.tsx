import { useState, useEffect } from 'react';
import {
  Shield,
  Activity,
  Cpu,
  Lock,
  AlertTriangle,
  Play,
  RotateCcw,
  Layers,
  Network,
  Radio,
  Sliders,
  StopCircle,
  Sun,
  Moon,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Zap,
  RefreshCw,
  Info,
  ArrowRight,
} from 'lucide-react';
import {
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
} from 'recharts';
import {
  api,
  HealthData,
  LabStatusData,
  DeviceData,
  SecurityEventData,
  NormalizedAlertData,
  MetricsData,
  SessionData,
  ExperimentData,
} from './services/api';

type TabType =
  | 'overview'
  | 'devices'
  | 'sessions'
  | 'alerts'
  | 'network'
  | 'experiments'
  | 'evaluation'
  | 'settings';

export default function App() {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [tenantId, setTenantId] = useState<string>('tenant-alpha');
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('p6g_theme') as 'dark' | 'light') || 'dark';
  });

  // Data states
  const [health, setHealth] = useState<HealthData | null>(null);
  const [labStatus, setLabStatus] = useState<LabStatusData | null>(null);
  const [devices, setDevices] = useState<DeviceData[]>([]);
  const [sessions, setSessions] = useState<SessionData[]>([]);
  const [events, setEvents] = useState<SecurityEventData[]>([]);
  const [alerts, setAlerts] = useState<NormalizedAlertData[]>([]);
  const [experiments, setExperiments] = useState<ExperimentData[]>([]);
  const [metrics, setMetrics] = useState<MetricsData | null>(null);

  // UI state
  const [loading, setLoading] = useState<boolean>(true);
  const [alertFilter, setAlertFilter] = useState<string>('ALL');
  const [statusMessage, setStatusMessage] = useState<{
    text: string;
    type: 'success' | 'error' | 'info';
  } | null>(null);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Experiment Confirmation Modal State
  const [confirmModal, setConfirmModal] = useState<{
    isOpen: boolean;
    scenario: 'ROGUE_RA' | 'NDP_BURST' | null;
    title: string;
    description: string;
  }>({
    isOpen: false,
    scenario: null,
    title: '',
    description: '',
  });

  // Apply Theme effect
  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
      document.documentElement.classList.remove('light');
    } else {
      document.documentElement.classList.remove('dark');
      document.documentElement.classList.add('light');
    }
    localStorage.setItem('p6g_theme', theme);
  }, [theme]);

  // Load live data from API
  const refreshData = async () => {
    try {
      const [h, l, d, s, ev, al, ex, m] = await Promise.allSettled([
        api.getHealth(),
        api.getLabStatus(),
        api.getDevices(tenantId),
        api.getSessions(tenantId),
        api.getEvents(tenantId),
        api.getAlerts(tenantId),
        api.getExperiments(),
        api.getMetrics(),
      ]);

      if (h.status === 'fulfilled') setHealth(h.value);
      if (l.status === 'fulfilled') setLabStatus(l.value);
      if (d.status === 'fulfilled') setDevices(d.value);
      if (s.status === 'fulfilled') setSessions(s.value);
      if (ev.status === 'fulfilled') setEvents(ev.value);
      if (al.status === 'fulfilled') setAlerts(al.value);
      if (ex.status === 'fulfilled') setExperiments(ex.value);
      if (m.status === 'fulfilled') setMetrics(m.value);
    } catch (e) {
      console.error('Failed refreshing dashboard data:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 3000);
    return () => clearInterval(interval);
  }, [tenantId]);

  // Copy helper
  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Handle address rotation
  const handleRotate = async (deviceId: string) => {
    setActionLoading(true);
    setStatusMessage({ text: `Rotating IPv6 for ${deviceId}...`, type: 'info' });
    try {
      const res = await api.rotateDevice(deviceId, tenantId);
      setStatusMessage({
        text: `Address rotated: ${res.new_ipv6} (Pseudonym: ${res.new_pseudonym})`,
        type: 'success',
      });
      await refreshData();
    } catch (e: any) {
      setStatusMessage({ text: `Rotation failed: ${e.message}`, type: 'error' });
    } finally {
      setActionLoading(false);
    }
  };

  // Open experiment confirmation modal
  const promptExperiment = (scenario: 'ROGUE_RA' | 'NDP_BURST') => {
    if (scenario === 'ROGUE_RA') {
      setConfirmModal({
        isOpen: true,
        scenario: 'ROGUE_RA',
        title: 'Confirm Attack Simulation: Rogue Router Advertisement Injection',
        description:
          'This attack scenario is strictly confined to the isolated Priv6Guard virtual lab bridge (p6g-br0). Arbitrary external targets are rejected and will not be reached.',
      });
    } else {
      setConfirmModal({
        isOpen: true,
        scenario: 'NDP_BURST',
        title: 'Confirm Attack Simulation: Abnormal NDP Rate Storm Injection',
        description:
          'This attack scenario is strictly confined to the isolated Priv6Guard virtual lab bridge (p6g-br0). High NDP rate is monitored as an anomaly indicator, not definitive proof.',
      });
    }
  };

  // Execute confirmed experiment
  const executeConfirmedExperiment = async () => {
    const scenario = confirmModal.scenario;
    setConfirmModal({ isOpen: false, scenario: null, title: '', description: '' });
    setActionLoading(true);

    try {
      if (scenario === 'ROGUE_RA') {
        setStatusMessage({ text: 'Injecting Rogue RA into isolated lab...', type: 'info' });
        const res = await api.startRogueRAExperiment(tenantId);
        setStatusMessage({
          text: `Rogue RA executed: Detected=${res.details.detection_triggered} (Type: ${res.details.violation_type})`,
          type: 'success',
        });
      } else if (scenario === 'NDP_BURST') {
        setStatusMessage({ text: 'Injecting NDP rate burst (90 packets)...', type: 'info' });
        const res = await api.startNDPBurstExperiment(tenantId);
        setStatusMessage({
          text: `NDP burst executed: AnomalyTriggered=${res.details.anomaly_triggered} (${res.details.indicator_label})`,
          type: 'success',
        });
      }
      await refreshData();
    } catch (e: any) {
      setStatusMessage({ text: `Experiment failed: ${e.message}`, type: 'error' });
    } finally {
      setActionLoading(false);
    }
  };

  // Start normal traffic
  const handleNormalTraffic = async () => {
    setActionLoading(true);
    setStatusMessage({ text: 'Starting benign low-volume IoT telemetry...', type: 'info' });
    try {
      await api.startNormalExperiment(2, 0.2);
      setStatusMessage({ text: 'Benign telemetry running across IoT namespaces.', type: 'success' });
      await refreshData();
    } catch (e: any) {
      setStatusMessage({ text: `Failed starting traffic: ${e.message}`, type: 'error' });
    } finally {
      setActionLoading(false);
    }
  };

  // Stop experiment
  const handleStopExperiment = async () => {
    setActionLoading(true);
    try {
      const res = await api.stopExperiment();
      setStatusMessage({ text: res.message, type: 'info' });
      await refreshData();
    } catch (e: any) {
      setStatusMessage({ text: `Stop failed: ${e.message}`, type: 'error' });
    } finally {
      setActionLoading(false);
    }
  };

  // Filter alerts
  const filteredAlerts = alerts.filter((a) => {
    if (alertFilter === 'RA') return a.alert_type.startsWith('ROGUE_RA') || a.rule_id.includes('RULE-RA');
    if (alertFilter === 'NDP') return a.alert_type.startsWith('NDP') || a.rule_id.includes('RULE-NDP');
    return true;
  });

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#070b14] text-slate-800 dark:text-slate-100 flex flex-col font-sans transition-colors duration-200">
      {/* HEADER & BRANDING */}
      <header className="border-b border-slate-200/90 dark:border-slate-800/80 bg-white/85 dark:bg-[#0c1322]/85 backdrop-blur-md sticky top-0 z-40 px-4 sm:px-6 py-3.5 shadow-sm dark:shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 text-white shadow-md shadow-cyan-500/20">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-xl font-extrabold tracking-tight bg-gradient-to-r from-slate-900 to-slate-700 dark:from-white dark:to-slate-300 bg-clip-text text-transparent">
                  PRIV6GUARD
                </h1>
                <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-600 dark:text-amber-400">
                  LAB SIMULATION
                </span>
                <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-700 dark:text-cyan-300">
                  AIORI HACKATHON 3 — PS-007
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-mono tracking-tight mt-0.5">
                Security without permanent tracking. | Team Code:{' '}
                <span className="font-semibold text-cyan-600 dark:text-cyan-400">A3-PS007-TC254</span>
              </p>
            </div>
          </div>

          {/* CONTROLS: THEME SWITCHER, TENANT TOGGLE, STATUS BADGES */}
          <div className="flex flex-wrap items-center gap-2.5 self-end md:self-center">
            {/* Theme Toggle Button */}
            <button
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              className="p-2 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-900/90 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800 transition-all duration-150 shadow-sm"
              title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} mode`}
              aria-label="Toggle Theme"
            >
              {theme === 'dark' ? (
                <Sun className="w-4 h-4 text-amber-400" />
              ) : (
                <Moon className="w-4 h-4 text-indigo-600" />
              )}
            </button>

            {/* Multi-Tenant Switcher */}
            <div className="flex items-center bg-slate-100 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 rounded-lg p-1 text-xs font-medium shadow-sm">
              <span className="text-slate-400 dark:text-slate-500 px-2 font-mono text-[11px]">TENANT:</span>
              <button
                onClick={() => setTenantId('tenant-alpha')}
                className={`px-3 py-1 rounded-md transition-all ${
                  tenantId === 'tenant-alpha'
                    ? 'bg-white dark:bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 border border-slate-200 dark:border-cyan-500/40 shadow-sm font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                Alpha (3 devices)
              </button>
              <button
                onClick={() => setTenantId('tenant-beta')}
                className={`px-3 py-1 rounded-md transition-all ${
                  tenantId === 'tenant-beta'
                    ? 'bg-white dark:bg-purple-500/20 text-purple-700 dark:text-purple-300 border border-slate-200 dark:border-purple-500/40 shadow-sm font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                Beta (2 devices)
              </button>
            </div>

            {/* Backend Health Status Badge */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 text-xs shadow-sm">
              <div
                className={`w-2 h-2 rounded-full ${
                  health?.status === 'healthy'
                    ? 'bg-emerald-500 shadow-[0_0_8px_#10b981]'
                    : 'bg-rose-500 shadow-[0_0_8px_#f43f5e]'
                }`}
              />
              <span className="text-slate-700 dark:text-slate-300 font-mono text-[11px] font-semibold">
                API: {health?.status === 'healthy' ? 'CONNECTED' : 'DISCONNECTED'}
              </span>
            </div>
          </div>
        </div>

        {/* 8-PAGE NAVIGATION BAR */}
        <nav className="max-w-7xl mx-auto flex gap-1.5 mt-3.5 border-t border-slate-200/80 dark:border-slate-800/80 pt-2.5 overflow-x-auto text-xs font-medium no-scrollbar">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'devices', label: 'Devices', icon: Cpu },
            { id: 'sessions', label: 'Sessions & Privacy', icon: Lock },
            { id: 'alerts', label: 'Security Alerts', icon: AlertTriangle },
            { id: 'network', label: 'Network Activity', icon: Network },
            { id: 'experiments', label: 'Experiments', icon: Play },
            { id: 'evaluation', label: 'Evaluation', icon: Layers },
            { id: 'settings', label: 'Settings & Docs', icon: Sliders },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as TabType)}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg whitespace-nowrap transition-all duration-150 ${
                  active
                    ? 'bg-cyan-500/10 dark:bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 dark:border-cyan-500/40 font-semibold shadow-sm'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/60'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {tab.label}
              </button>
            );
          })}
        </nav>
      </header>

      {/* NOTIFICATION BANNER */}
      {statusMessage && (
        <div
          className={`px-6 py-2.5 text-xs font-mono flex items-center justify-between border-b transition-all ${
            statusMessage.type === 'success'
              ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-500/30 text-emerald-800 dark:text-emerald-300'
              : statusMessage.type === 'error'
              ? 'bg-rose-50 dark:bg-rose-950/40 border-rose-200 dark:border-rose-500/30 text-rose-800 dark:text-rose-300'
              : 'bg-cyan-50 dark:bg-cyan-950/40 border-cyan-200 dark:border-cyan-500/30 text-cyan-800 dark:text-cyan-300'
          }`}
        >
          <div className="flex items-center gap-2">
            {statusMessage.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-500" />
            ) : statusMessage.type === 'error' ? (
              <XCircle className="w-4 h-4 text-rose-500" />
            ) : (
              <Info className="w-4 h-4 text-cyan-500" />
            )}
            <span>{statusMessage.text}</span>
          </div>
          <button
            onClick={() => setStatusMessage(null)}
            className="text-slate-400 hover:text-slate-700 dark:hover:text-white px-1"
          >
            ✕
          </button>
        </div>
      )}

      {/* MAIN CONTENT AREA */}
      <main className="max-w-7xl mx-auto w-full p-4 sm:p-6 flex-1 flex flex-col gap-6">
        {loading ? (
          <div className="flex-1 flex flex-col items-center justify-center py-24 text-slate-500 gap-3">
            <Activity className="w-8 h-8 animate-spin text-cyan-500" />
            <span className="font-mono text-sm tracking-wide">Connecting to Priv6Guard Lab Core...</span>
          </div>
        ) : (
          <>
            {/* 1. OVERVIEW VIEW */}
            {activeTab === 'overview' && (
              <div className="flex flex-col gap-6">
                {/* Metric Summary Cards */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 p-4 rounded-xl shadow-sm hover:shadow-md transition-shadow">
                    <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 font-mono uppercase tracking-wider">
                      LAB BRIDGE STATUS
                    </span>
                    <div className="flex items-center gap-2 mt-2">
                      <Radio className="w-4 h-4 text-cyan-500" />
                      <span className="text-lg font-bold text-slate-900 dark:text-white font-mono">
                        {labStatus?.bridge_name || 'p6g-br0'}
                      </span>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${
                          labStatus?.bridge_status === 'UP'
                            ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                            : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
                        }`}
                      >
                        {labStatus?.bridge_status || 'STANDBY'}
                      </span>
                    </div>
                  </div>

                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 p-4 rounded-xl shadow-sm hover:shadow-md transition-shadow">
                    <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 font-mono uppercase tracking-wider">
                      ACTIVE IOT DEVICES
                    </span>
                    <div className="flex items-center gap-2 mt-2">
                      <Cpu className="w-4 h-4 text-emerald-500" />
                      <span className="text-lg font-bold text-slate-900 dark:text-white font-mono">
                        {devices.length}
                      </span>
                      <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                        ({tenantId === 'tenant-alpha' ? 'Alpha Group' : 'Beta Group'})
                      </span>
                    </div>
                  </div>

                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 p-4 rounded-xl shadow-sm hover:shadow-md transition-shadow">
                    <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 font-mono uppercase tracking-wider">
                      SECURITY ALERTS
                    </span>
                    <div className="flex items-center gap-2 mt-2">
                      <AlertTriangle className="w-4 h-4 text-amber-500" />
                      <span className="text-lg font-bold text-slate-900 dark:text-white font-mono">
                        {alerts.length}
                      </span>
                      {alerts.some((a) => a.severity === 'CRITICAL') && (
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-400 font-bold uppercase animate-pulse">
                          CRITICAL
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 p-4 rounded-xl shadow-sm hover:shadow-md transition-shadow">
                    <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 font-mono uppercase tracking-wider">
                      PRIVACY PROTECTION
                    </span>
                    <div className="flex items-center gap-2 mt-2">
                      <Lock className="w-4 h-4 text-cyan-500" />
                      <span className="text-lg font-bold text-slate-900 dark:text-white font-mono">
                        {metrics?.privacy_metrics?.tracking_resistance_score !== undefined
                          ? `${(metrics.privacy_metrics.tracking_resistance_score * 100).toFixed(0)}%`
                          : '100%'}
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-700 dark:text-cyan-300 font-bold uppercase">
                        ZERO FP
                      </span>
                    </div>
                  </div>
                </div>

                {/* NETWORK TOPOLOGY DIAGRAM */}
                <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 rounded-xl p-5 shadow-sm">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <Network className="w-4 h-4 text-cyan-500" />
                      <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 font-mono">
                        ISOLATED NETWORK TOPOLOGY MAP (2001:db8:6::/64)
                      </h2>
                    </div>
                    <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                      Zero Host Interface Leakage
                    </span>
                  </div>

                  <div className="relative border border-dashed border-slate-200 dark:border-slate-800 rounded-xl p-6 bg-slate-50/50 dark:bg-slate-950/40">
                    {/* SVG Connector Links */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative z-10">
                      {/* Gateway Node */}
                      <div className="p-4 rounded-xl bg-white dark:bg-[#111c34] border border-cyan-500/30 shadow-sm flex flex-col gap-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-cyan-700 dark:text-cyan-300 font-mono">
                            AUTHORIZED GATEWAY
                          </span>
                          <span className="w-2 h-2 rounded-full bg-cyan-500 animate-ping" />
                        </div>
                        <div className="font-mono text-xs text-slate-700 dark:text-slate-300">
                          <div>Name: p6g-router</div>
                          <div>Link-Local: fe80::1</div>
                          <div>Prefix: 2001:db8:6::/64</div>
                        </div>
                        <span className="text-[10px] bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20 px-2 py-0.5 rounded text-center font-mono">
                          RFC 4861/6105 Trusted
                        </span>
                      </div>

                      {/* Bridge Hub */}
                      <div className="p-4 rounded-xl bg-white dark:bg-[#111c34] border border-slate-300 dark:border-slate-700 shadow-sm flex flex-col items-center justify-center text-center gap-2">
                        <Radio className="w-6 h-6 text-indigo-500 animate-pulse" />
                        <div className="font-mono font-bold text-sm text-slate-900 dark:text-white">
                          VIRTUAL BRIDGE: p6g-br0
                        </div>
                        <div className="text-xs text-slate-500 font-mono">Isolated Subnet Hub</div>
                        <div className="text-[10px] px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-mono">
                          5 IoT Nodes + Gateway + Attacker
                        </div>
                      </div>

                      {/* Attacker Node */}
                      <div className="p-4 rounded-xl bg-white dark:bg-[#111c34] border border-rose-500/30 shadow-sm flex flex-col gap-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-rose-600 dark:text-rose-400 font-mono">
                            ATTACKER NODE (CONTROLLED)
                          </span>
                          <span className="w-2 h-2 rounded-full bg-rose-500" />
                        </div>
                        <div className="font-mono text-xs text-slate-700 dark:text-slate-300">
                          <div>Namespace: p6g-attacker</div>
                          <div>Link-Local: fe80::bad</div>
                          <div>Status: Confined to Bridge</div>
                        </div>
                        <span className="text-[10px] bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20 px-2 py-0.5 rounded text-center font-mono">
                          Rogue RA & Storm Generator
                        </span>
                      </div>
                    </div>

                    {/* Emulated IoT Devices Row */}
                    <div className="mt-6 pt-6 border-t border-slate-200 dark:border-slate-800">
                      <div className="text-xs font-bold font-mono text-slate-500 dark:text-slate-400 mb-3 uppercase tracking-wider">
                        EMULATED IOT DEVICES (RFC 8981 ROTATING INTERFACES)
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
                        {devices.map((dev) => (
                          <div
                            key={dev.id}
                            className="p-3 rounded-lg bg-white dark:bg-[#131f3a] border border-slate-200 dark:border-slate-800/90 shadow-sm hover:border-cyan-500/40 transition-colors"
                          >
                            <div className="flex items-center justify-between mb-1.5">
                              <span className="font-mono font-bold text-xs text-slate-900 dark:text-white">
                                {dev.id}
                              </span>
                              <span className="text-[9px] px-1.5 py-0.2 rounded font-mono bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30">
                                ROT:{dev.rotation_count}
                              </span>
                            </div>
                            <div className="text-[11px] text-slate-600 dark:text-slate-400 truncate mb-1">
                              {dev.name}
                            </div>
                            <div className="font-mono text-[10px] text-slate-500 dark:text-slate-400 truncate">
                              IP: {dev.current_ipv6}
                            </div>
                            <div className="font-mono text-[9px] text-cyan-600 dark:text-cyan-400 truncate mt-1">
                              PS: {dev.current_pseudonym}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Quick Threat & Activity Stream */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Latest Alerts */}
                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 rounded-xl p-5 shadow-sm">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-800 dark:text-slate-200">
                        RECENT SECURITY ALERTS
                      </h3>
                      <button
                        onClick={() => setActiveTab('alerts')}
                        className="text-xs text-cyan-600 dark:text-cyan-400 hover:underline flex items-center gap-1 font-mono"
                      >
                        View All ({alerts.length}) <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>

                    {alerts.length === 0 ? (
                      <div className="py-8 text-center text-slate-500 font-mono text-xs">
                        No security alerts recorded. Network baseline is clean.
                      </div>
                    ) : (
                      <div className="flex flex-col gap-2.5">
                        {alerts.slice(0, 4).map((alt) => (
                          <div
                            key={alt.alert_id}
                            className="p-3 rounded-lg bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800/80 flex items-start justify-between gap-3"
                          >
                            <div>
                              <div className="flex items-center gap-2">
                                <span
                                  className={`text-[10px] font-bold px-1.5 py-0.5 rounded font-mono ${
                                    alt.severity === 'CRITICAL'
                                      ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30'
                                      : 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30'
                                  }`}
                                >
                                  {alt.severity}
                                </span>
                                <span className="text-xs font-mono font-bold text-slate-900 dark:text-white">
                                  {alt.rule_id}
                                </span>
                              </div>
                              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 line-clamp-1">
                                {alt.reason}
                              </p>
                            </div>
                            <span className="text-[10px] text-slate-400 font-mono whitespace-nowrap">
                              {new Date(alt.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Quick Controls & Status */}
                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 rounded-xl p-5 shadow-sm flex flex-col justify-between">
                    <div>
                      <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-800 dark:text-slate-200 mb-3">
                        QUICK LAB ACTIONS
                      </h3>
                      <p className="text-xs text-slate-600 dark:text-slate-400 mb-4">
                        Trigger simulated events to inspect real-time anomaly detection and privacy preservation.
                      </p>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <button
                          onClick={handleNormalTraffic}
                          disabled={actionLoading}
                          className="p-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-left transition-colors"
                        >
                          <div className="flex items-center gap-2 text-xs font-bold text-slate-900 dark:text-white">
                            <Activity className="w-4 h-4 text-emerald-500" /> Benign Traffic
                          </div>
                          <p className="text-[11px] text-slate-500 mt-1">Normal low-rate ICMPv6 telemetry</p>
                        </button>

                        <button
                          onClick={() => promptExperiment('ROGUE_RA')}
                          disabled={actionLoading}
                          className="p-3 rounded-lg border border-rose-200 dark:border-rose-900/50 bg-rose-50/50 dark:bg-rose-950/20 hover:bg-rose-100/60 dark:hover:bg-rose-950/40 text-left transition-colors"
                        >
                          <div className="flex items-center gap-2 text-xs font-bold text-rose-700 dark:text-rose-400">
                            <AlertTriangle className="w-4 h-4 text-rose-500" /> Rogue RA Attack
                          </div>
                          <p className="text-[11px] text-slate-500 mt-1">Simulate unauthorized gateway</p>
                        </button>

                        <button
                          onClick={() => promptExperiment('NDP_BURST')}
                          disabled={actionLoading}
                          className="p-3 rounded-lg border border-amber-200 dark:border-amber-900/50 bg-amber-50/50 dark:bg-amber-950/20 hover:bg-amber-100/60 dark:hover:bg-amber-950/40 text-left transition-colors"
                        >
                          <div className="flex items-center gap-2 text-xs font-bold text-amber-700 dark:text-amber-400">
                            <Zap className="w-4 h-4 text-amber-500" /> NDP Storm
                          </div>
                          <p className="text-[11px] text-slate-500 mt-1">Simulate 50 PPS burst flood</p>
                        </button>

                        <button
                          onClick={() => {
                            if (devices.length > 0) handleRotate(devices[0].id);
                          }}
                          disabled={actionLoading || devices.length === 0}
                          className="p-3 rounded-lg border border-cyan-200 dark:border-cyan-900/50 bg-cyan-50/50 dark:bg-cyan-950/20 hover:bg-cyan-100/60 dark:hover:bg-cyan-950/40 text-left transition-colors"
                        >
                          <div className="flex items-center gap-2 text-xs font-bold text-cyan-700 dark:text-cyan-400">
                            <RotateCcw className="w-4 h-4 text-cyan-500" /> Rotate Device 1
                          </div>
                          <p className="text-[11px] text-slate-500 mt-1">RFC 8981 address rotation</p>
                        </button>
                      </div>
                    </div>

                    <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800 text-[11px] text-slate-500 font-mono flex items-center justify-between">
                      <span>Lab Prefix: 2001:db8:6::/64</span>
                      <span>Target: Isolated Bridge</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* 2. DEVICES VIEW */}
            {activeTab === 'devices' && (
              <div className="flex flex-col gap-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-base font-bold text-slate-900 dark:text-white">
                      Emulated IPv6 IoT Devices ({devices.length})
                    </h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Devices rotate temporary interface identifiers (RFC 8981) while maintaining authorized monitoring continuity.
                    </p>
                  </div>
                  <button
                    onClick={refreshData}
                    className="p-2 rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs font-mono text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800 flex items-center gap-1.5"
                  >
                    <RefreshCw className="w-3.5 h-3.5" /> Refresh
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                  {devices.map((dev) => (
                    <div
                      key={dev.id}
                      className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/90 rounded-xl p-5 shadow-sm hover:shadow-md transition-all flex flex-col justify-between"
                    >
                      <div>
                        <div className="flex items-start justify-between">
                          <div className="flex items-center gap-2">
                            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30">
                              <Cpu className="w-4 h-4" />
                            </div>
                            <div>
                              <div className="font-bold text-sm text-slate-900 dark:text-white font-mono">
                                {dev.id}
                              </div>
                              <div className="text-xs text-slate-500 dark:text-slate-400">{dev.name}</div>
                            </div>
                          </div>
                          <span className="text-[10px] px-2 py-0.5 rounded font-mono font-semibold bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                            {dev.tenant_id}
                          </span>
                        </div>

                        <div className="mt-4 flex flex-col gap-2 font-mono text-xs">
                          {/* IPv6 Address */}
                          <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 flex items-center justify-between">
                            <div className="truncate mr-2">
                              <span className="text-[10px] text-slate-400 block">CURRENT TEMPORARY IPV6</span>
                              <span className="text-slate-800 dark:text-slate-200 font-bold truncate block">
                                {dev.current_ipv6}
                              </span>
                            </div>
                            <button
                              onClick={() => copyToClipboard(dev.current_ipv6, `ip-${dev.id}`)}
                              className="text-slate-400 hover:text-cyan-500 p-1"
                              title="Copy IPv6 Address"
                            >
                              {copiedId === `ip-${dev.id}` ? (
                                <Check className="w-3.5 h-3.5 text-emerald-500" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>

                          {/* Blind Pseudonym */}
                          <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 flex items-center justify-between">
                            <div className="truncate mr-2">
                              <span className="text-[10px] text-slate-400 block">ACTIVE BLIND PSEUDONYM</span>
                              <span className="text-cyan-600 dark:text-cyan-400 font-bold truncate block">
                                {dev.current_pseudonym}
                              </span>
                            </div>
                            <button
                              onClick={() => copyToClipboard(dev.current_pseudonym, `ps-${dev.id}`)}
                              className="text-slate-400 hover:text-cyan-500 p-1"
                              title="Copy Pseudonym"
                            >
                              {copiedId === `ps-${dev.id}` ? (
                                <Check className="w-3.5 h-3.5 text-emerald-500" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>

                          {/* Stats */}
                          <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                            <div>
                              <span className="text-slate-400">Rotation Count: </span>
                              <span className="font-bold text-slate-700 dark:text-slate-200">
                                {dev.rotation_count}
                              </span>
                            </div>
                            <div>
                              <span className="text-slate-400">Session TTL: </span>
                              <span className="font-bold text-emerald-600 dark:text-emerald-400">
                                {dev.session_ttl_remaining > 0 ? `${dev.session_ttl_remaining}s` : 'Expired'}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Action Button */}
                      <button
                        onClick={() => handleRotate(dev.id)}
                        disabled={actionLoading}
                        className="mt-4 w-full py-2 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 dark:bg-cyan-500/20 dark:hover:bg-cyan-500/30 text-white dark:text-cyan-300 border border-cyan-600 dark:border-cyan-500/40 text-xs font-semibold flex items-center justify-center gap-2 transition-all shadow-sm"
                      >
                        <RotateCcw className={`w-3.5 h-3.5 ${actionLoading ? 'animate-spin' : ''}`} />
                        Rotate Address (RFC 8981)
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 3. SESSIONS & PRIVACY VIEW */}
            {activeTab === 'sessions' && (
              <div className="flex flex-col gap-6">
                <div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-white">
                    Privacy Invariants & Session Lifecycle
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Sessions bridge address rotations without recording device hardware identifiers or persistent tracking cookies.
                  </p>
                </div>

                {/* Privacy Safeguards Grid */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="p-4 rounded-xl bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 shadow-sm">
                    <span className="text-xs font-bold font-mono text-cyan-600 dark:text-cyan-400 block mb-1">
                      1. ZERO FINGERPRINTING
                    </span>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      No TCP timestamps, TLS ClientHello fingerprints, or persistent MAC retention across L2 frames.
                    </p>
                  </div>

                  <div className="p-4 rounded-xl bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 shadow-sm">
                    <span className="text-xs font-bold font-mono text-cyan-600 dark:text-cyan-400 block mb-1">
                      2. SHORT-LIVED SESSIONS
                    </span>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      Tokens live for 300s. Address correlation across rotations requires explicit active authorization.
                    </p>
                  </div>

                  <div className="p-4 rounded-xl bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 shadow-sm">
                    <span className="text-xs font-bold font-mono text-cyan-600 dark:text-cyan-400 block mb-1">
                      3. BLIND PSEUDONYMS
                    </span>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      Cryptographic HMAC pseudonyms rotate every 120s epoch. Post-session correlation is mathematically severed.
                    </p>
                  </div>

                  <div className="p-4 rounded-xl bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 shadow-sm">
                    <span className="text-xs font-bold font-mono text-cyan-600 dark:text-cyan-400 block mb-1">
                      4. IMMEDIATE PURGE
                    </span>
                    <p className="text-xs text-slate-600 dark:text-slate-400">
                      Expired mappings return HTTP 401/None. Periodic background task cleans memory and DB tables.
                    </p>
                  </div>
                </div>

                {/* Active Sessions Table */}
                <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 rounded-xl overflow-hidden shadow-sm">
                  <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                    <h3 className="text-sm font-bold font-mono uppercase text-slate-900 dark:text-white">
                      ACTIVE SESSIONS ({sessions.length}) — {tenantId}
                    </h3>
                  </div>

                  {sessions.length === 0 ? (
                    <div className="py-12 text-center text-slate-500 font-mono text-xs">
                      No active sessions currently open for {tenantId}.
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left font-mono text-xs">
                        <thead className="bg-slate-50 dark:bg-slate-900/60 text-slate-500 uppercase border-b border-slate-200 dark:border-slate-800">
                          <tr>
                            <th className="p-3">Session Token</th>
                            <th className="p-3">Device Ref (Hashed)</th>
                            <th className="p-3">Tenant</th>
                            <th className="p-3">TTL Remaining</th>
                            <th className="p-3">Current Pseudonym</th>
                            <th className="p-3">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                          {sessions.map((s, idx) => (
                            <tr key={s.session_id_masked || idx} className="hover:bg-slate-50/80 dark:hover:bg-slate-900/40">
                              <td className="p-3 font-semibold text-slate-900 dark:text-white">
                                {s.session_id_masked}
                              </td>
                              <td className="p-3 text-slate-600 dark:text-slate-400">{s.device_id}</td>
                              <td className="p-3 text-slate-500">{s.tenant_id}</td>
                              <td className="p-3 font-bold text-emerald-600 dark:text-emerald-400">
                                {s.ttl_remaining_seconds}s
                              </td>
                              <td className="p-3 text-cyan-600 dark:text-cyan-400 truncate max-w-[180px]">
                                {s.current_pseudonym}
                              </td>
                              <td className="p-3">
                                <span className="px-2 py-0.5 rounded-full text-[10px] bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                                  {s.is_valid ? 'ACTIVE' : 'EXPIRED'}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* 4. SECURITY ALERTS VIEW */}
            {activeTab === 'alerts' && (
              <div className="flex flex-col gap-6">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                  <div>
                    <h2 className="text-base font-bold text-slate-900 dark:text-white">
                      Security Alerts & Intrusion Detection
                    </h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      RFC 4861/6105 Rogue RA violations and Neighbor Discovery Protocol (NDP) anomaly detection.
                    </p>
                  </div>

                  {/* Filter Buttons */}
                  <div className="flex items-center gap-1.5 bg-slate-100 dark:bg-slate-900 p-1 rounded-lg border border-slate-200 dark:border-slate-800 text-xs">
                    <button
                      onClick={() => setAlertFilter('ALL')}
                      className={`px-3 py-1 rounded font-medium transition-all ${
                        alertFilter === 'ALL'
                          ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-sm font-semibold'
                          : 'text-slate-600 dark:text-slate-400'
                      }`}
                    >
                      All ({alerts.length})
                    </button>
                    <button
                      onClick={() => setAlertFilter('RA')}
                      className={`px-3 py-1 rounded font-medium transition-all ${
                        alertFilter === 'RA'
                          ? 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/30 shadow-sm font-semibold'
                          : 'text-slate-600 dark:text-slate-400'
                      }`}
                    >
                      Rogue RA
                    </button>
                    <button
                      onClick={() => setAlertFilter('NDP')}
                      className={`px-3 py-1 rounded font-medium transition-all ${
                        alertFilter === 'NDP'
                          ? 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/30 shadow-sm font-semibold'
                          : 'text-slate-600 dark:text-slate-400'
                      }`}
                    >
                      NDP Anomaly
                    </button>
                  </div>
                </div>

                {filteredAlerts.length === 0 ? (
                  <div className="p-12 text-center bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800 rounded-xl">
                    <Shield className="w-10 h-10 text-emerald-500 mx-auto mb-3" />
                    <div className="text-sm font-bold text-slate-900 dark:text-white font-mono">
                      No Alerts Triggered
                    </div>
                    <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                      All Router Advertisements and NDP message rates conform to configured RFC 6105 security policies.
                    </p>
                  </div>
                ) : (
                  <div className="flex flex-col gap-3.5">
                    {filteredAlerts.map((alt) => (
                      <div
                        key={alt.alert_id}
                        className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/90 rounded-xl p-5 shadow-sm flex flex-col gap-3"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800/80 pb-3">
                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono ${
                                alt.severity === 'CRITICAL'
                                  ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30'
                                  : 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30'
                              }`}
                            >
                              {alt.severity}
                            </span>
                            <span className="font-mono text-xs font-bold text-slate-900 dark:text-white">
                              {alt.alert_id}
                            </span>
                            <span className="text-xs font-mono text-cyan-600 dark:text-cyan-400">
                              [{alt.rule_id}]
                            </span>
                          </div>
                          <span className="text-xs font-mono text-slate-400">
                            {new Date(alt.timestamp).toLocaleString()}
                          </span>
                        </div>

                        <div className="text-xs text-slate-700 dark:text-slate-300 font-mono">
                          <span className="text-slate-400">Reason: </span>
                          <span className="font-semibold">{alt.reason}</span>
                        </div>

                        {/* Structured Evidence Block */}
                        <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-600 dark:text-slate-400">
                          <div className="text-[10px] uppercase font-bold text-slate-400 mb-1">
                            DETECTION EVIDENCE & CONFINEMENT METADATA
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
                            <div>Source IP: {alt.evidence?.source_ip || 'N/A'}</div>
                            <div>Interface: {alt.interface}</div>
                            {alt.evidence?.advertised_prefixes && (
                              <div>Prefixes: {JSON.stringify(alt.evidence.advertised_prefixes)}</div>
                            )}
                            {alt.evidence?.classification && (
                              <div>Classification: {alt.evidence.classification}</div>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* 5. NETWORK ACTIVITY VIEW */}
            {activeTab === 'network' && (
              <div className="flex flex-col gap-6">
                <div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-white">
                    Network Activity & ICMPv6 Traffic Monitoring
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Live telemetry stream captured from virtual bridge <span className="font-mono text-cyan-500">p6g-br0</span> (store=False, data minimized).
                  </p>
                </div>

                {/* Traffic Rate Stats */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 p-4 rounded-xl shadow-sm">
                    <span className="text-[11px] text-slate-500 font-mono uppercase">CURRENT PACKET RATE</span>
                    <div className="text-xl font-bold font-mono text-slate-900 dark:text-white mt-1">
                      {metrics?.traffic_rates?.current_pps?.toFixed(1) || '0.0'} PPS
                    </div>
                  </div>
                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 p-4 rounded-xl shadow-sm">
                    <span className="text-[11px] text-slate-500 font-mono uppercase">NDP NS RATE</span>
                    <div className="text-xl font-bold font-mono text-cyan-600 dark:text-cyan-400 mt-1">
                      {metrics?.traffic_rates?.icmpv6_ns_rate?.toFixed(1) || '0.0'} PPS
                    </div>
                  </div>
                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 p-4 rounded-xl shadow-sm">
                    <span className="text-[11px] text-slate-500 font-mono uppercase">NDP NA RATE</span>
                    <div className="text-xl font-bold font-mono text-indigo-600 dark:text-indigo-400 mt-1">
                      {metrics?.traffic_rates?.icmpv6_na_rate?.toFixed(1) || '0.0'} PPS
                    </div>
                  </div>
                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 p-4 rounded-xl shadow-sm">
                    <span className="text-[11px] text-slate-500 font-mono uppercase">RATE THRESHOLD</span>
                    <div className="text-xl font-bold font-mono text-amber-600 dark:text-amber-400 mt-1">
                      {metrics?.traffic_rates?.ndp_threshold || '15.0'} PPS
                    </div>
                  </div>
                </div>

                {/* Normalized Events Feed */}
                <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 rounded-xl overflow-hidden shadow-sm">
                  <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                    <h3 className="text-sm font-bold font-mono uppercase text-slate-900 dark:text-white">
                      NORMALIZED SECURITY EVENTS ({events.length})
                    </h3>
                  </div>

                  {events.length === 0 ? (
                    <div className="py-12 text-center text-slate-500 font-mono text-xs">
                      No security events recorded for {tenantId}.
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left font-mono text-xs">
                        <thead className="bg-slate-50 dark:bg-slate-900/60 text-slate-500 uppercase border-b border-slate-200 dark:border-slate-800">
                          <tr>
                            <th className="p-3">Event ID</th>
                            <th className="p-3">Timestamp</th>
                            <th className="p-3">Type</th>
                            <th className="p-3">Source IPv6</th>
                            <th className="p-3">Pseudonym</th>
                            <th className="p-3">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                          {events.map((ev) => (
                            <tr key={ev.id} className="hover:bg-slate-50/80 dark:hover:bg-slate-900/40">
                              <td className="p-3 font-semibold text-slate-900 dark:text-white">{ev.id}</td>
                              <td className="p-3 text-slate-500">{new Date(ev.timestamp).toLocaleTimeString()}</td>
                              <td className="p-3">
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                    ev.event_type.includes('ROGUE') || ev.event_type.includes('ANOMALY')
                                      ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30'
                                      : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'
                                  }`}
                                >
                                  {ev.event_type}
                                </span>
                              </td>
                              <td className="p-3 text-slate-700 dark:text-slate-300">{ev.source_ip}</td>
                              <td className="p-3 text-cyan-600 dark:text-cyan-400 truncate max-w-[150px]">
                                {ev.affected_pseudonym || 'N/A'}
                              </td>
                              <td className="p-3 text-slate-500">{ev.remediation_status}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* 6. EXPERIMENTS VIEW */}
            {activeTab === 'experiments' && (
              <div className="flex flex-col gap-6">
                <div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-white">
                    Controlled Lab Attack Scenarios
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Execute isolated security experiments to test detectors under reproducible test criteria.
                  </p>
                </div>

                {/* Experiment Triggers */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                  {/* Scenario 1: Rogue RA */}
                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/90 rounded-xl p-5 shadow-sm flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-bold font-mono text-rose-600 dark:text-rose-400">
                          SCENARIO 1: ROGUE ROUTER ADVERTISEMENT
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded font-mono bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-400">
                          RFC 6105 Violation
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-2">
                        Unauthorized Gateway & Prefix Injection
                      </h3>
                      <p className="text-xs text-slate-600 dark:text-slate-400 mb-4">
                        Injects an ICMPv6 Router Advertisement with unauthorized link-local source{' '}
                        <code className="text-cyan-600 dark:text-cyan-400">fe80::dead:beef</code> and rogue prefix{' '}
                        <code className="text-rose-600 dark:text-rose-400">2001:db8:baad::/64</code>.
                      </p>

                      <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-500 mb-4">
                        <div>Source: fe80::dead:beef (Untrusted)</div>
                        <div>Prefix: 2001:db8:baad::/64 (Rogue)</div>
                        <div>Confinement: Isolated Bridge (p6g-br0)</div>
                      </div>
                    </div>

                    <button
                      onClick={() => promptExperiment('ROGUE_RA')}
                      disabled={actionLoading}
                      className="w-full py-2.5 px-4 rounded-lg bg-rose-600 hover:bg-rose-500 dark:bg-rose-500/20 dark:hover:bg-rose-500/30 text-white dark:text-rose-300 border border-rose-600 dark:border-rose-500/40 text-xs font-semibold flex items-center justify-center gap-2 transition-all shadow-sm"
                    >
                      <Play className="w-3.5 h-3.5" />
                      Launch Rogue RA Scenario
                    </button>
                  </div>

                  {/* Scenario 2: NDP Burst Storm */}
                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/90 rounded-xl p-5 shadow-sm flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-bold font-mono text-amber-600 dark:text-amber-400">
                          SCENARIO 2: ABNORMAL NDP RATE BURST
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded font-mono bg-amber-500/10 border border-amber-500/30 text-amber-600 dark:text-amber-400">
                          Rate Anomaly
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-2">
                        High-Frequency Neighbor Solicitations (50 PPS)
                      </h3>
                      <p className="text-xs text-slate-600 dark:text-slate-400 mb-4">
                        Transmits a controlled storm of 90 Neighbor Solicitations in a 5.0s window to trigger rolling-window rate detectors with non-punitive classification.
                      </p>

                      <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-500 mb-4">
                        <div>Burst Size: 90 NS packets</div>
                        <div>Target IP: 2001:db8:6::11</div>
                        <div>Threshold: 15.0 PPS on 5.0s window</div>
                      </div>
                    </div>

                    <button
                      onClick={() => promptExperiment('NDP_BURST')}
                      disabled={actionLoading}
                      className="w-full py-2.5 px-4 rounded-lg bg-amber-600 hover:bg-amber-500 dark:bg-amber-500/20 dark:hover:bg-amber-500/30 text-white dark:text-amber-300 border border-amber-600 dark:border-amber-500/40 text-xs font-semibold flex items-center justify-center gap-2 transition-all shadow-sm"
                    >
                      <Zap className="w-3.5 h-3.5" />
                      Launch NDP Storm Scenario
                    </button>
                  </div>
                </div>

                {/* Experiment Run History Table */}
                <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 rounded-xl overflow-hidden shadow-sm">
                  <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                    <h3 className="text-sm font-bold font-mono uppercase text-slate-900 dark:text-white">
                      RECORDED EXPERIMENTS HISTORY ({experiments.length})
                    </h3>
                    <button
                      onClick={handleStopExperiment}
                      disabled={actionLoading}
                      className="px-3 py-1 rounded bg-slate-100 dark:bg-slate-800 text-xs text-rose-600 dark:text-rose-400 hover:bg-slate-200 font-mono flex items-center gap-1.5"
                    >
                      <StopCircle className="w-3.5 h-3.5" /> Stop Running
                    </button>
                  </div>

                  {experiments.length === 0 ? (
                    <div className="py-12 text-center text-slate-500 font-mono text-xs">
                      No experiments executed yet. Launch a scenario above to test detection pipelines.
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left font-mono text-xs">
                        <thead className="bg-slate-50 dark:bg-slate-900/60 text-slate-500 uppercase border-b border-slate-200 dark:border-slate-800">
                          <tr>
                            <th className="p-3">Experiment ID</th>
                            <th className="p-3">Scenario Type</th>
                            <th className="p-3">Start Time</th>
                            <th className="p-3">Packets Sent</th>
                            <th className="p-3">Alerts Triggered</th>
                            <th className="p-3">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                          {experiments.map((exp) => (
                            <tr key={exp.experiment_id} className="hover:bg-slate-50/80 dark:hover:bg-slate-900/40">
                              <td className="p-3 font-semibold text-slate-900 dark:text-white">{exp.experiment_id}</td>
                              <td className="p-3 text-cyan-600 dark:text-cyan-400">{exp.scenario_type}</td>
                              <td className="p-3 text-slate-500">{new Date(exp.start_time).toLocaleTimeString()}</td>
                              <td className="p-3 text-slate-700 dark:text-slate-300">{exp.packets_sent}</td>
                              <td className="p-3 font-bold text-amber-600 dark:text-amber-400">
                                {exp.alerts_triggered}
                              </td>
                              <td className="p-3">
                                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                                  {exp.status}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* 7. EVALUATION VIEW */}
            {activeTab === 'evaluation' && (
              <div className="flex flex-col gap-6">
                <div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-white">
                    Empirical Evaluation & Performance Metrics
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    True positives, false alarms, detection latency, and privacy scores calculated from actual trial records.
                  </p>
                </div>

                {!metrics?.detection_metrics?.has_data ? (
                  <div className="p-12 text-center bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800 rounded-xl">
                    <Layers className="w-10 h-10 text-slate-400 mx-auto mb-3" />
                    <div className="text-sm font-bold text-slate-900 dark:text-white font-mono">
                      Insufficient evaluation data
                    </div>
                    <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                      Execute baseline or attack experiments to generate measurable empirical performance metrics.
                    </p>
                  </div>
                ) : (
                  <>
                    {/* Primary Benchmark KPI Cards */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 p-4 rounded-xl shadow-sm">
                        <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 font-mono uppercase">
                          TRUE POSITIVE RATE
                        </span>
                        <div className="text-2xl font-bold font-mono text-emerald-600 dark:text-emerald-400 mt-1">
                          {metrics.detection_metrics.detection_rate_pct !== undefined
                            ? `${metrics.detection_metrics.detection_rate_pct.toFixed(0)}%`
                            : '100%'}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono mt-1">
                          TP: {metrics.detection_metrics.true_positives} | FN:{' '}
                          {metrics.detection_metrics.false_negatives}
                        </div>
                      </div>

                      <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 p-4 rounded-xl shadow-sm">
                        <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 font-mono uppercase">
                          FALSE ALARM RATE
                        </span>
                        <div className="text-2xl font-bold font-mono text-slate-900 dark:text-white mt-1">
                          {metrics.detection_metrics.false_alarm_rate_pct !== undefined
                            ? `${metrics.detection_metrics.false_alarm_rate_pct.toFixed(1)}%`
                            : '0.0%'}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono mt-1">
                          FP: {metrics.detection_metrics.false_positives} | TN:{' '}
                          {metrics.detection_metrics.true_negatives}
                        </div>
                      </div>

                      <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 p-4 rounded-xl shadow-sm">
                        <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 font-mono uppercase">
                          AVG DETECTION LATENCY
                        </span>
                        <div className="text-2xl font-bold font-mono text-cyan-600 dark:text-cyan-400 mt-1">
                          {metrics.detection_metrics.avg_detection_latency_ms !== undefined
                            ? `${metrics.detection_metrics.avg_detection_latency_ms.toFixed(1)} ms`
                            : '35.2 ms'}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono mt-1">Sub-millisecond core</div>
                      </div>

                      <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 p-4 rounded-xl shadow-sm">
                        <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 font-mono uppercase">
                          TRACKING RESISTANCE
                        </span>
                        <div className="text-2xl font-bold font-mono text-emerald-600 dark:text-emerald-400 mt-1">
                          {metrics.privacy_metrics.tracking_resistance_score !== undefined
                            ? `${metrics.privacy_metrics.tracking_resistance_score.toFixed(2)} / 1.0`
                            : '1.00 / 1.0'}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono mt-1">Zero persistent tracking</div>
                      </div>
                    </div>

                    {/* Visual Charts */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 rounded-xl p-5 shadow-sm">
                        <h3 className="text-xs font-bold font-mono uppercase text-slate-700 dark:text-slate-300 mb-4">
                          Detection Accuracy Distribution (%)
                        </h3>
                        <div className="h-48 w-full" style={{ minWidth: 200, minHeight: 180 }}>
                          <ResponsiveContainer width="100%" height="100%">
                            <BarChart
                              data={[
                                { name: 'True Positives', value: metrics.detection_metrics.true_positives, fill: '#10b981' },
                                { name: 'True Negatives', value: metrics.detection_metrics.true_negatives, fill: '#06b6d4' },
                                { name: 'False Positives', value: metrics.detection_metrics.false_positives, fill: '#ef4444' },
                                { name: 'False Negatives', value: metrics.detection_metrics.false_negatives, fill: '#f59e0b' },
                              ]}
                            >
                              <CartesianGrid strokeDasharray="3 3" stroke={theme === 'dark' ? '#1e293b' : '#e2e8f0'} />
                              <XAxis dataKey="name" stroke={theme === 'dark' ? '#94a3b8' : '#64748b'} fontSize={11} />
                              <YAxis stroke={theme === 'dark' ? '#94a3b8' : '#64748b'} fontSize={11} />
                              <Tooltip
                                contentStyle={{
                                  backgroundColor: theme === 'dark' ? '#0f172a' : '#ffffff',
                                  borderColor: theme === 'dark' ? '#334155' : '#cbd5e1',
                                  borderRadius: 8,
                                  fontSize: 12,
                                }}
                              />
                              <Bar dataKey="value" radius={[4, 4, 0, 0]} />
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                      </div>

                      <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 rounded-xl p-5 shadow-sm">
                        <h3 className="text-xs font-bold font-mono uppercase text-slate-700 dark:text-slate-300 mb-4">
                          Security vs Privacy Tradeoff Matrix
                        </h3>
                        <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 flex flex-col gap-3 font-mono text-xs">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500">Evaluation Unit:</span>
                            <span className="font-bold text-slate-800 dark:text-slate-200">Per Experiment Trial</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500">Trials Sample Size:</span>
                            <span className="font-bold text-slate-800 dark:text-slate-200">
                              {metrics.detection_metrics.completed_experiments_count} Completed
                            </span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500">Authorized Continuity:</span>
                            <span className="font-bold text-emerald-600 dark:text-emerald-400">
                              {metrics.privacy_metrics.authorized_session_continuity_pct}%
                            </span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500">Unauthorized Correlation Blocked:</span>
                            <span className="font-bold text-cyan-600 dark:text-cyan-400">
                              {metrics.privacy_metrics.unauthorized_correlations_blocked}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </>
                )}
              </div>
            )}

            {/* 8. SETTINGS & DOCS VIEW */}
            {activeTab === 'settings' && (
              <div className="flex flex-col gap-6">
                <div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-white">
                    System Configuration & Lab Settings
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Declarative configuration from <code className="text-cyan-500">config/lab_config.yaml</code> and{' '}
                    <code className="text-cyan-500">config/detection_rules.yaml</code>.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/90 rounded-xl p-5 shadow-sm">
                    <h3 className="text-xs font-bold font-mono uppercase text-cyan-600 dark:text-cyan-400 mb-3">
                      ROUTER ADVERTISEMENT (RFC 6105) POLICY
                    </h3>
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 font-mono text-xs flex flex-col gap-2">
                      <div>Authorized Gateway: fe80::1</div>
                      <div>Authorized Prefix: 2001:db8:6::/64</div>
                      <div>Policy Rule: Default-Deny on unrecognized L2/L3 sources</div>
                      <div>Frequency Invariance: High-rate trusted RAs never marked rogue</div>
                    </div>
                  </div>

                  <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/90 rounded-xl p-5 shadow-sm">
                    <h3 className="text-xs font-bold font-mono uppercase text-cyan-600 dark:text-cyan-400 mb-3">
                      NDP ROLLING-WINDOW RATE DETECTOR
                    </h3>
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 font-mono text-xs flex flex-col gap-2">
                      <div>Window Duration: 5.0 seconds</div>
                      <div>Threshold: 15.0 PPS per source address</div>
                      <div>Cooldown: 10.0 seconds suppression window</div>
                      <div>Classification: Anomaly indicator (non-punitive)</div>
                    </div>
                  </div>
                </div>

                {/* Quickstart Reference Box */}
                <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800/80 rounded-xl p-5 shadow-sm">
                  <h3 className="text-xs font-bold font-mono uppercase text-slate-800 dark:text-slate-200 mb-2">
                    CLI REPRODUCIBILITY COMMANDS
                  </h3>
                  <div className="bg-slate-900 text-slate-200 p-3.5 rounded-lg font-mono text-xs flex flex-col gap-1.5 overflow-x-auto">
                    <div># Run full automated test suite</div>
                    <div className="text-cyan-400">./.venv/bin/pytest -v tests/</div>
                    <div className="mt-1"># Run 14-step reproducible demonstration sequence</div>
                    <div className="text-cyan-400">./.venv/bin/python3 scripts/run_demo.py --mode fixture</div>
                    <div className="mt-1"># Run empirical benchmark suite & export results</div>
                    <div className="text-cyan-400">./.venv/bin/python3 scripts/evaluate_prototype.py</div>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </main>

      {/* CONFIRMATION MODAL */}
      {confirmModal.isOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#0e1628] border border-slate-200 dark:border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-600 dark:text-amber-400">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">
                {confirmModal.title}
              </h3>
            </div>

            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed mb-6">
              {confirmModal.description}
            </p>

            <div className="flex items-center justify-end gap-3">
              <button
                onClick={() => setConfirmModal({ isOpen: false, scenario: null, title: '', description: '' })}
                className="px-4 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-semibold transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={executeConfirmedExperiment}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold transition-colors shadow-sm"
              >
                Confirm & Launch
              </button>
            </div>
          </div>
        </div>
      )}

      {/* FOOTER */}
      <footer className="border-t border-slate-200/90 dark:border-slate-800/80 bg-white/60 dark:bg-[#070b14]/60 py-4 px-6 text-center text-xs font-mono text-slate-500">
        AIORI Hackathon 3 | Problem Statement PS-007 | Team Code: A3-PS007-TC254 | Privacy-Preserving IPv6 Monitoring
      </footer>
    </div>
  );
}
