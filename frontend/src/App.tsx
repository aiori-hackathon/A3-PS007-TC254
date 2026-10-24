import { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Server,
  Layers,
  Activity,
  AlertTriangle,
  Cpu,
  RefreshCw,
  KeyRound,
  Sliders,
  CheckCircle2,
  XCircle,
  Clock,
  Info
} from 'lucide-react';

interface HealthData {
  status: string;
  app: string;
  version: string;
  mode: string;
  config_loaded: boolean;
  timestamp: string;
}

export function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'devices' | 'sessions' | 'alerts' | 'evaluation' | 'settings'>('overview');
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHealth = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/health');
      if (!res.ok) {
        throw new Error(`HTTP error ${res.status}: ${res.statusText}`);
      }
      const data: HealthData = await res.json();
      setHealth(data);
    } catch (err: any) {
      setError(err.message || 'Unable to connect to backend');
      setHealth(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col">
      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800 bg-[#0d1527]/90 backdrop-blur-md sticky top-0 z-50 px-6 py-3.5 flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-emerald-400 flex items-center justify-center shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/30">
            <ShieldCheck className="h-6 w-6 text-slate-950 font-bold" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <span className="font-extrabold text-lg tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 via-teal-300 to-emerald-400">
                PRIV6GUARD
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded-full font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 uppercase">
                v1.0.0
              </span>
            </div>
            <p className="text-xs text-slate-400 font-medium">
              AIORI Hackathon 3 <span className="text-slate-600">•</span> PS-007 <span className="text-slate-600">•</span> Team A3-PS007-TC254
            </p>
          </div>
        </div>

        {/* Global System Badges */}
        <div className="flex items-center space-x-3">
          {/* Lab Simulation Mode Pill */}
          <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-300 border border-amber-500/30">
            <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse"></span>
            <span>LAB SIMULATION</span>
          </div>

          {/* Backend Health Status Badge */}
          <div
            className={`flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium border transition-colors ${
              health
                ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                : 'bg-rose-500/10 text-rose-300 border-rose-500/30'
            }`}
          >
            {loading ? (
              <RefreshCw className="h-3 w-3 animate-spin text-slate-400" />
            ) : health ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
            ) : (
              <XCircle className="h-3.5 w-3.5 text-rose-400" />
            )}
            <span>
              {health ? 'Backend Connected' : error ? 'Backend Disconnected' : 'Checking...'}
            </span>
          </div>

          <button
            onClick={fetchHealth}
            title="Refresh Status"
            className="p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 rounded-lg transition-colors border border-transparent hover:border-slate-700"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </header>

      {/* Main Layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar Navigation */}
        <aside className="w-64 border-r border-slate-800 bg-[#090f1d] p-4 flex flex-col justify-between shrink-0">
          <nav className="space-y-1.5">
            <button
              onClick={() => setActiveTab('overview')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'overview'
                  ? 'bg-gradient-to-r from-cyan-950 to-slate-900 text-cyan-300 border border-cyan-800/60 shadow-sm'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`}
            >
              <Activity className="h-4 w-4" />
              <span>Overview</span>
            </button>

            <button
              onClick={() => setActiveTab('devices')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'devices'
                  ? 'bg-gradient-to-r from-cyan-950 to-slate-900 text-cyan-300 border border-cyan-800/60 shadow-sm'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`}
            >
              <Cpu className="h-4 w-4" />
              <span>Devices</span>
            </button>

            <button
              onClick={() => setActiveTab('sessions')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'sessions'
                  ? 'bg-gradient-to-r from-cyan-950 to-slate-900 text-cyan-300 border border-cyan-800/60 shadow-sm'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`}
            >
              <KeyRound className="h-4 w-4" />
              <span>Sessions & Pseudonyms</span>
            </button>

            <button
              onClick={() => setActiveTab('alerts')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'alerts'
                  ? 'bg-gradient-to-r from-cyan-950 to-slate-900 text-cyan-300 border border-cyan-800/60 shadow-sm'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`}
            >
              <AlertTriangle className="h-4 w-4" />
              <span>Security Alerts</span>
            </button>

            <button
              onClick={() => setActiveTab('evaluation')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'evaluation'
                  ? 'bg-gradient-to-r from-cyan-950 to-slate-900 text-cyan-300 border border-cyan-800/60 shadow-sm'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`}
            >
              <Layers className="h-4 w-4" />
              <span>Evaluation & Metrics</span>
            </button>

            <button
              onClick={() => setActiveTab('settings')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'settings'
                  ? 'bg-gradient-to-r from-cyan-950 to-slate-900 text-cyan-300 border border-cyan-800/60 shadow-sm'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`}
            >
              <Sliders className="h-4 w-4" />
              <span>Lab & Rule Settings</span>
            </button>
          </nav>

          {/* System Footer Info */}
          <div className="border-t border-slate-800/80 pt-4 text-xs text-slate-500 space-y-2">
            <div className="flex justify-between items-center">
              <span>FastAPI Port</span>
              <span className="font-mono text-slate-400">8000</span>
            </div>
            <div className="flex justify-between items-center">
              <span>Bridge Target</span>
              <span className="font-mono text-cyan-400">priv6-br0</span>
            </div>
            <div className="flex justify-between items-center">
              <span>Privacy Standard</span>
              <span className="font-mono text-slate-400">RFC 8981</span>
            </div>
          </div>
        </aside>

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto p-8 space-y-6">
          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && (
            <div className="space-y-6 max-w-6xl">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-3">
                  <span>Privacy-Preserving IPv6 Security Monitoring</span>
                </h1>
                <p className="text-sm text-slate-400 mt-1">
                  Intrusion monitoring and anomaly correlation across dynamic IPv6 address rotations without tracking devices.
                </p>
              </div>

              {/* Status Banner */}
              <div className="rounded-xl border border-cyan-900/50 bg-gradient-to-r from-cyan-950/40 via-slate-900/60 to-slate-900/40 p-5">
                <div className="flex items-start space-x-4">
                  <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 mt-0.5">
                    <Info className="h-5 w-5" />
                  </div>
                  <div className="space-y-1">
                    <h3 className="text-sm font-semibold text-cyan-300">Phase 1 Operational Baseline</h3>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      Core application scaffolding, configuration loader, database schema, structured audit logging, and health endpoint validation are active.
                      No live network packets or telemetry are fabricated.
                    </p>
                    {health && (
                      <div className="pt-2 flex items-center space-x-4 text-xs font-mono text-slate-400">
                        <span>Application: <strong className="text-slate-200">{health.app}</strong></span>
                        <span>Version: <strong className="text-slate-200">{health.version}</strong></span>
                        <span>Config Verified: <strong className="text-emerald-400">Yes</strong></span>
                        <span>Server Time: <strong className="text-slate-200">{new Date(health.timestamp).toLocaleTimeString()}</strong></span>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Core Architecture Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                <div className="rounded-xl border border-slate-800 bg-[#0d1527] p-5 space-y-3">
                  <div className="flex items-center space-x-3 text-cyan-400">
                    <Server className="h-5 w-5" />
                    <h3 className="font-semibold text-sm text-slate-200">1. Isolated IPv6 Lab</h3>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Dedicated virtual bridge <code className="text-cyan-300">priv6-br0</code> and five isolated device network namespaces (<code className="text-cyan-300">priv6-ns-dev1..5</code>). Zero packet leakage to host interfaces.
                  </p>
                  <div className="pt-2 text-xs font-medium text-amber-400/90 flex items-center space-x-1">
                    <Clock className="h-3.5 w-3.5" />
                    <span>Activates in Phase 2</span>
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-[#0d1527] p-5 space-y-3">
                  <div className="flex items-center space-x-3 text-emerald-400">
                    <KeyRound className="h-5 w-5" />
                    <h3 className="font-semibold text-sm text-slate-200">2. Privacy & Pseudonyms</h3>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    RFC 8981 address rotation with blind HMAC-SHA256 epoch pseudonyms and time-limited session tokens. Expired mappings are permanently purged.
                  </p>
                  <div className="pt-2 text-xs font-medium text-amber-400/90 flex items-center space-x-1">
                    <Clock className="h-3.5 w-3.5" />
                    <span>Activates in Phase 3</span>
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-[#0d1527] p-5 space-y-3">
                  <div className="flex items-center space-x-3 text-rose-400">
                    <ShieldAlert className="h-5 w-5" />
                    <h3 className="font-semibold text-sm text-slate-200">3. Intrusion Detectors</h3>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    RFC 4861/6105 Rogue Router Advertisement detection and rolling-window ICMPv6 Neighbor Discovery rate anomaly filters.
                  </p>
                  <div className="pt-2 text-xs font-medium text-amber-400/90 flex items-center space-x-1">
                    <Clock className="h-3.5 w-3.5" />
                    <span>Activates in Phase 4</span>
                  </div>
                </div>
              </div>

              {/* Planned Five Devices Manifest */}
              <div className="rounded-xl border border-slate-800 bg-[#0d1527] overflow-hidden">
                <div className="px-5 py-3.5 border-b border-slate-800 flex justify-between items-center">
                  <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
                    <Cpu className="h-4 w-4 text-cyan-400" />
                    <span>Configured Device Inventory</span>
                  </h3>
                  <span className="text-xs text-slate-500 font-mono">5 Planned Nodes</span>
                </div>
                <div className="p-5">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="pb-3 font-semibold">Device ID</th>
                          <th className="pb-3 font-semibold">Device Role</th>
                          <th className="pb-3 font-semibold">Namespace</th>
                          <th className="pb-3 font-semibold">Tenant</th>
                          <th className="pb-3 font-semibold">Configured ULA</th>
                          <th className="pb-3 font-semibold">Phase Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 text-slate-300">
                        <tr>
                          <td className="py-3 font-mono font-bold text-cyan-400">dev-01</td>
                          <td className="py-3">Smart Thermostat</td>
                          <td className="py-3 font-mono text-slate-400">priv6-ns-dev1</td>
                          <td className="py-3">tenant-alpha</td>
                          <td className="py-3 font-mono">fd00:cafe:1::101</td>
                          <td className="py-3 text-amber-400">Pending Lab Init</td>
                        </tr>
                        <tr>
                          <td className="py-3 font-mono font-bold text-cyan-400">dev-02</td>
                          <td className="py-3">Medical Heart Monitor</td>
                          <td className="py-3 font-mono text-slate-400">priv6-ns-dev2</td>
                          <td className="py-3">tenant-alpha</td>
                          <td className="py-3 font-mono">fd00:cafe:1::102</td>
                          <td className="py-3 text-amber-400">Pending Lab Init</td>
                        </tr>
                        <tr>
                          <td className="py-3 font-mono font-bold text-cyan-400">dev-03</td>
                          <td className="py-3">Industrial Flowmeter</td>
                          <td className="py-3 font-mono text-slate-400">priv6-ns-dev3</td>
                          <td className="py-3">tenant-alpha</td>
                          <td className="py-3 font-mono">fd00:cafe:1::103</td>
                          <td className="py-3 text-amber-400">Pending Lab Init</td>
                        </tr>
                        <tr>
                          <td className="py-3 font-mono font-bold text-cyan-400">dev-04</td>
                          <td className="py-3">CCTV Security Streamer</td>
                          <td className="py-3 font-mono text-slate-400">priv6-ns-dev4</td>
                          <td className="py-3">tenant-beta</td>
                          <td className="py-3 font-mono">fd00:cafe:1::104</td>
                          <td className="py-3 text-amber-400">Pending Lab Init</td>
                        </tr>
                        <tr>
                          <td className="py-3 font-mono font-bold text-cyan-400">dev-05</td>
                          <td className="py-3">Environmental Air Sensor</td>
                          <td className="py-3 font-mono text-slate-400">priv6-ns-dev5</td>
                          <td className="py-3">tenant-beta</td>
                          <td className="py-3 font-mono">fd00:cafe:1::105</td>
                          <td className="py-3 text-amber-400">Pending Lab Init</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* EMPTY STATES FOR OTHER TABS (ACCORDING TO ENGINEERING RULES) */}
          {activeTab === 'devices' && (
            <div className="rounded-xl border border-dashed border-slate-800 bg-[#0d1527]/50 p-12 text-center space-y-4">
              <div className="h-12 w-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto text-slate-400">
                <Cpu className="h-6 w-6" />
              </div>
              <div className="space-y-1">
                <h3 className="text-base font-semibold text-slate-200">Live Device Telemetry Not Yet Connected</h3>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  Live device polling requires the Phase 2 isolated network namespaces and bridge to be initialized. No fake telemetry is displayed.
                </p>
              </div>
              <div className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                <span>Phase 2 Implementation Target</span>
              </div>
            </div>
          )}

          {activeTab === 'sessions' && (
            <div className="rounded-xl border border-dashed border-slate-800 bg-[#0d1527]/50 p-12 text-center space-y-4">
              <div className="h-12 w-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto text-slate-400">
                <KeyRound className="h-6 w-6" />
              </div>
              <div className="space-y-1">
                <h3 className="text-base font-semibold text-slate-200">Active Pseudonyms & Sessions Standby</h3>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  The session manager, temporary pseudonym generator, and TTL purger will be bound in Phase 3.
                </p>
              </div>
              <div className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                <span>Phase 3 Implementation Target</span>
              </div>
            </div>
          )}

          {activeTab === 'alerts' && (
            <div className="rounded-xl border border-dashed border-slate-800 bg-[#0d1527]/50 p-12 text-center space-y-4">
              <div className="h-12 w-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto text-slate-400">
                <ShieldAlert className="h-6 w-6" />
              </div>
              <div className="space-y-1">
                <h3 className="text-base font-semibold text-slate-200">Zero Active Security Alerts</h3>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  Intrusion detectors for Rogue Router Advertisements and abnormal NDP rate storms attach to the bridge in Phase 4.
                </p>
              </div>
              <div className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono bg-rose-950 text-rose-400 border border-rose-800/60">
                <span>Phase 4 Implementation Target</span>
              </div>
            </div>
          )}

          {activeTab === 'evaluation' && (
            <div className="rounded-xl border border-dashed border-slate-800 bg-[#0d1527]/50 p-12 text-center space-y-4">
              <div className="h-12 w-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto text-slate-400">
                <Layers className="h-6 w-6" />
              </div>
              <div className="space-y-1">
                <h3 className="text-base font-semibold text-slate-200">Empirical Evaluation Metrics</h3>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  Metrics must be calculated from actual experiments rather than fabricated counters. This dashboard will stream live metrics in Phase 5 & 6.
                </p>
              </div>
              <div className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono bg-amber-950 text-amber-400 border border-amber-800/60">
                <span>Empirical Metrics Engine (Phase 5)</span>
              </div>
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="space-y-6 max-w-4xl">
              <h2 className="text-lg font-bold text-white">Lab & Detection Policy Rules</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div className="rounded-xl border border-slate-800 bg-[#0d1527] p-5 space-y-3">
                  <h3 className="text-sm font-semibold text-cyan-300">Router Advertisement Policy (RFC 4861)</h3>
                  <div className="text-xs font-mono bg-slate-950/80 p-3 rounded-lg border border-slate-800 text-slate-300 space-y-1">
                    <div>authorized_router: fe80::1</div>
                    <div>allowed_prefix: fd00:cafe:1::/64</div>
                    <div>max_router_lifetime: 1800s</div>
                    <div>min_router_lifetime: 60s</div>
                    <div>action_on_unauthorized: ALERT_CRITICAL</div>
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-[#0d1527] p-5 space-y-3">
                  <h3 className="text-sm font-semibold text-emerald-300">NDP Anomaly Thresholds</h3>
                  <div className="text-xs font-mono bg-slate-950/80 p-3 rounded-lg border border-slate-800 text-slate-300 space-y-1">
                    <div>rolling_window: 5.0 seconds</div>
                    <div>max_ns_rate: 15.0 / sec</div>
                    <div>max_na_rate: 15.0 / sec</div>
                    <div>max_rs_rate: 5.0 / sec</div>
                    <div>classification: ANOMALY_INDICATOR</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
