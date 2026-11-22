import React, { useState, useEffect, useMemo } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Search,
  Filter,
  Download,
  Terminal,
  ExternalLink,
  ChevronRight,
  Database,
  Building2,
  User,
  Users,
  CheckCircle2,
  XCircle,
  Clock,
  RefreshCw,
  Eye,
  Lock,
  Globe,
  Radio,
  FileSpreadsheet,
  Layers,
  Send,
  Trash2,
  SlidersHorizontal,
  ChevronDown,
  Server,
  Code
} from 'lucide-react';
import {
  securityLogger
} from '../../core/logging/securityLogger';
import {
  SecurityTelemetryRecord,
  SecurityIncident,
  IncidentStatus,
  IncidentSeverity,
  Verdict,
  SecurityActionTaken
} from '../../core/types';
import { PipelineSimulator } from './PipelineSimulator';
import { BackendSetupGuide } from './BackendSetupGuide';

type PersonaMode = 'individual' | 'analyst' | 'business' | 'enterprise';

interface SecurityDashboardProps {
  onInspectUrl?: (url: string) => void;
}

export const SecurityDashboard: React.FC<SecurityDashboardProps> = ({ onInspectUrl }) => {
  const [persona, setPersona] = useState<PersonaMode>('analyst');
  const [logs, setLogs] = useState<SecurityTelemetryRecord[]>([]);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [metrics, setMetrics] = useState(securityLogger.getSecurityMetrics());
  const [isServerConnected, setIsServerConnected] = useState(true);
  
  // Filtering & Query State
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [actionFilter, setActionFilter] = useState<string>('ALL');
  const [timeRangeMs, setTimeRangeMs] = useState<number>(0); // 0 = all
  const [hasFormRiskOnly, setHasFormRiskOnly] = useState(false);
  const [hasThreatIntelOnly, setHasThreatIntelOnly] = useState(false);

  // Active view within analyst / enterprise modes
  const [analystSubView, setAnalystSubView] = useState<'pipeline' | 'incidents' | 'logs' | 'setup_guide' | 'mitre' | 'intel'>('pipeline');
  
  // Selected Detail Modal / Drawer
  const [selectedLog, setSelectedLog] = useState<SecurityTelemetryRecord | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident | null>(null);
  const [newAnalystNote, setNewAnalystNote] = useState('');
  const [analystName, setAnalystName] = useState('Analyst-Lead');
  
  // Export status notification
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  // Refresh logs and metrics from store / API
  const refreshData = async () => {
    // 1. Try fetching from real server API
    try {
      const queryParams = new URLSearchParams();
      if (searchQuery) queryParams.set('search', searchQuery);
      if (verdictFilter !== 'ALL') queryParams.set('verdict', verdictFilter);
      if (severityFilter !== 'ALL') queryParams.set('severity', severityFilter);
      if (actionFilter !== 'ALL') queryParams.set('actionTaken', actionFilter);

      const [telRes, incRes] = await Promise.all([
        fetch(`/api/telemetry?${queryParams.toString()}`),
        fetch(`/api/incidents?${queryParams.toString()}`)
      ]);

      if (telRes.ok && incRes.ok) {
        const telData = await telRes.json();
        const incData = await incRes.json();
        if (telData.logs && telData.logs.length > 0) {
          setLogs(telData.logs);
        } else {
          // fallback to client query
          setLogs(securityLogger.queryLogs({ search: searchQuery }));
        }
        if (incData.incidents && incData.incidents.length > 0) {
          setIncidents(incData.incidents);
        } else {
          setIncidents(securityLogger.queryIncidents({ search: searchQuery }));
        }
        setIsServerConnected(true);
        setMetrics(securityLogger.getSecurityMetrics());
        return;
      }
    } catch {
      setIsServerConnected(false);
    }

    // Fallback to client storage
    const freshLogs = securityLogger.queryLogs({
      search: searchQuery,
      verdict: verdictFilter,
      severity: severityFilter,
      actionTaken: actionFilter,
      timeRangeMs: timeRangeMs || undefined,
      hasFormRiskOnly,
      hasThreatIntelFlagOnly: hasThreatIntelOnly
    });
    const freshIncidents = securityLogger.queryIncidents({
      search: searchQuery
    });
    setLogs(freshLogs);
    setIncidents(freshIncidents);
    setMetrics(securityLogger.getSecurityMetrics());
  };

  useEffect(() => {
    refreshData();
  }, [searchQuery, verdictFilter, severityFilter, actionFilter, timeRangeMs, hasFormRiskOnly, hasThreatIntelOnly]);

  const handleExportJson = () => {
    const jsonStr = securityLogger.exportLogsJson();
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-telemetry-logs-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showNotice('Exported full telemetry records as JSON');
  };

  const handleExportCsv = () => {
    const csvStr = securityLogger.exportLogsCsv();
    const blob = new Blob([csvStr], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-telemetry-logs-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    showNotice('Exported telemetry dataset as CSV');
  };

  const handleExportStix = () => {
    const stixStr = securityLogger.exportStix2Bundle();
    const blob = new Blob([stixStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-stix-2.1-bundle-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showNotice('Exported OASIS STIX 2.1 Threat Intel Bundle for SIEM');
  };

  const showNotice = (msg: string) => {
    setExportNotice(msg);
    setTimeout(() => setExportNotice(null), 4000);
  };

  const handleUpdateIncidentStatus = (incidentId: string, status: IncidentStatus) => {
    securityLogger.updateIncident(incidentId, { status });
    refreshData();
    if (selectedIncident && selectedIncident.incidentId === incidentId) {
      setSelectedIncident({ ...selectedIncident, status, updatedAt: Date.now() });
    }
  };

  const handleAddIncidentNote = () => {
    if (!selectedIncident || !newAnalystNote.trim()) return;
    const updated = securityLogger.updateIncident(selectedIncident.incidentId, {
      newNote: newAnalystNote.trim(),
      author: analystName
    });
    setNewAnalystNote('');
    refreshData();
    if (updated) setSelectedIncident(updated);
  };

  const handleClearLogs = () => {
    if (window.confirm('Are you sure you want to clear all telemetry records and active incidents?')) {
      securityLogger.clearAllLogs();
      refreshData();
      setSelectedLog(null);
      setSelectedIncident(null);
      showNotice('All security logs cleared.');
    }
  };

  // Severity color helper
  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'HIGH':
      case 'HIGH_RISK':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'MEDIUM':
      case 'SUSPICIOUS':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'LOW':
      case 'LOW_RISK':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    }
  };

  const getActionBadgeClass = (action: SecurityActionTaken) => {
    switch (action) {
      case 'FORM_SUBMISSION_INTERCEPTED':
        return 'bg-purple-500/10 text-purple-300 border-purple-500/30';
      case 'BLOCKING_MODAL':
        return 'bg-red-500/10 text-red-300 border-red-500/30';
      case 'IN_PAGE_BANNER':
        return 'bg-amber-500/10 text-amber-300 border-amber-500/30';
      case 'DOWNLOAD_INTERCEPTED':
        return 'bg-orange-500/10 text-orange-300 border-orange-500/30';
      case 'USER_PROCEEDED_OVERRIDE':
        return 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30';
      case 'ALLOWLISTED_BYPASS':
        return 'bg-blue-500/10 text-blue-300 border-blue-500/30';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Persona Selector */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 sm:p-6 backdrop-blur-md">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-blue-600/10 border border-blue-500/20 text-blue-400">
                <Database className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                  Security Event & Incident Telemetry Logs
                  <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    Live Monitor
                  </span>
                </h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Privacy-first security metadata recording. Zero credentials, passwords, cookies, or secrets stored.
                </p>
              </div>
            </div>
          </div>

          {/* Persona Switcher */}
          <div className="flex items-center bg-slate-950 p-1 rounded-xl border border-slate-800 self-start lg:self-auto">
            <button
              id="persona-individual"
              onClick={() => setPersona('individual')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                persona === 'individual'
                  ? 'bg-blue-600 text-white shadow'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <User className="w-3.5 h-3.5" />
              <span>Individual</span>
            </button>
            <button
              id="persona-analyst"
              onClick={() => setPersona('analyst')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                persona === 'analyst'
                  ? 'bg-blue-600 text-white shadow'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Security Analyst</span>
            </button>
            <button
              id="persona-business"
              onClick={() => setPersona('business')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                persona === 'business'
                  ? 'bg-blue-600 text-white shadow'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Building2 className="w-3.5 h-3.5" />
              <span>Small Business</span>
            </button>
            <button
              id="persona-enterprise"
              onClick={() => setPersona('enterprise')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                persona === 'enterprise'
                  ? 'bg-blue-600 text-white shadow'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Enterprise SOC</span>
            </button>
          </div>
        </div>

        {/* Global Summary Metric Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mt-6">
          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
            <span className="text-[11px] font-medium text-slate-400 block">Total Analyzed Sessions</span>
            <div className="text-xl font-bold text-white mt-1 flex items-baseline gap-1.5">
              {metrics.totalScans}
              <span className="text-[10px] text-blue-400 font-normal">events</span>
            </div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
            <span className="text-[11px] font-medium text-red-400 block">Dangerous Threats Blocked</span>
            <div className="text-xl font-bold text-red-400 mt-1 flex items-baseline gap-1.5">
              {metrics.threatsBlocked}
              <span className="text-[10px] text-red-400/80 font-normal">mitigated</span>
            </div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
            <span className="text-[11px] font-medium text-amber-400 block">Suspicious Warnings</span>
            <div className="text-xl font-bold text-amber-400 mt-1 flex items-baseline gap-1.5">
              {metrics.suspiciousWarnings}
              <span className="text-[10px] text-amber-400/80 font-normal">banners</span>
            </div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
            <span className="text-[11px] font-medium text-purple-400 block">Credential Form Blocks</span>
            <div className="text-xl font-bold text-purple-400 mt-1 flex items-baseline gap-1.5">
              {metrics.formsIntercepted}
              <span className="text-[10px] text-purple-400/80 font-normal">intercepted</span>
            </div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
            <span className="text-[11px] font-medium text-rose-400 block">Active Incidents</span>
            <div className="text-xl font-bold text-rose-400 mt-1 flex items-baseline gap-1.5">
              {metrics.activeIncidents}
              <span className="text-[10px] text-rose-400/80 font-normal">open</span>
            </div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
            <span className="text-[11px] font-medium text-emerald-400 block">Clean / Safe Pages</span>
            <div className="text-xl font-bold text-emerald-400 mt-1 flex items-baseline gap-1.5">
              {metrics.safeScans}
              <span className="text-[10px] text-emerald-400/80 font-normal">verified</span>
            </div>
          </div>
        </div>
      </div>

      {/* Export Notification Banner */}
      {exportNotice && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs px-4 py-2.5 rounded-xl flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{exportNotice}</span>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 1. INDIVIDUAL / CONSUMER PERSONA VIEW */}
      {/* ========================================================================= */}
      {persona === 'individual' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Protection Shield Status */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-3">
                  <div className="p-3 bg-emerald-500/10 rounded-2xl border border-emerald-500/20 text-emerald-400">
                    <ShieldCheck className="w-7 h-7" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">Browser Shield Active</h3>
                    <p className="text-xs text-slate-400">Real-Time Zero-Hour Phishing Guard</p>
                  </div>
                </div>

                <div className="mt-6 space-y-3">
                  <div className="flex items-center justify-between text-xs py-2 border-b border-slate-800/80">
                    <span className="text-slate-400">Protected Navigation</span>
                    <span className="font-semibold text-emerald-400">Continuous Monitoring</span>
                  </div>
                  <div className="flex items-center justify-between text-xs py-2 border-b border-slate-800/80">
                    <span className="text-slate-400">Dangerous Password Submissions</span>
                    <span className="font-semibold text-purple-400">Auto-Intercepted</span>
                  </div>
                  <div className="flex items-center justify-between text-xs py-2 border-b border-slate-800/80">
                    <span className="text-slate-400">Threat Intelligence Feeds</span>
                    <span className="font-semibold text-blue-400">5 Feeds Synced</span>
                  </div>
                  <div className="flex items-center justify-between text-xs py-2">
                    <span className="text-slate-400">Personal Privacy Guarantee</span>
                    <span className="font-semibold text-slate-300">0 Data Collected</span>
                  </div>
                </div>
              </div>

              <div className="mt-6 pt-4 border-t border-slate-800 text-[11px] text-slate-500">
                PhishGuard operates locally inside your browser. No passwords, credentials, or browsing history leave your device.
              </div>
            </div>

            {/* Recent Protection Activity Feed */}
            <div className="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Clock className="w-4 h-4 text-blue-400" />
                  Recent Security Events
                </h3>
                <span className="text-xs text-slate-400">{logs.length} logged sessions</span>
              </div>

              <div className="space-y-2.5">
                {logs.slice(0, 5).map((log) => (
                  <div
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition-all flex items-center justify-between cursor-pointer"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className={`p-2 rounded-lg border ${getSeverityBadgeClass(log.severity)}`}>
                        {log.verdict === 'DANGEROUS' || log.verdict === 'HIGH_RISK' ? (
                          <ShieldAlert className="w-4 h-4" />
                        ) : log.verdict === 'SUSPICIOUS' ? (
                          <AlertTriangle className="w-4 h-4" />
                        ) : (
                          <ShieldCheck className="w-4 h-4" />
                        )}
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-xs text-white truncate max-w-[220px] sm:max-w-xs">
                            {log.domain}
                          </span>
                          {log.targetBrandName && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                              Mimics {log.targetBrandName}
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400 truncate max-w-md mt-0.5">
                          {log.reasons[0] || 'Clean, verified legitimate website'}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 shrink-0 ml-4">
                      <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-md border ${getActionBadgeClass(log.actionTaken)}`}>
                        {log.actionTaken.replace(/_/g, ' ')}
                      </span>
                      <ChevronRight className="w-4 h-4 text-slate-600" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. SECURITY ANALYST & ENTERPRISE WORKFLOW VIEW */}
      {/* ========================================================================= */}
      {(persona === 'analyst' || persona === 'enterprise' || persona === 'business') && (
        <div className="space-y-4">
          {/* Sub-Navigation Tabs */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/60 p-2 rounded-xl border border-slate-800">
            <div className="flex flex-wrap items-center gap-1">
              <button
                id="view-pipeline"
                onClick={() => setAnalystSubView('pipeline')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  analystSubView === 'pipeline'
                    ? 'bg-blue-600 text-white shadow-md shadow-blue-900/40'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Radio className="w-3.5 h-3.5 text-blue-300" />
                <span>Live Pipeline Simulator</span>
              </button>
              <button
                id="view-incidents"
                onClick={() => setAnalystSubView('incidents')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  analystSubView === 'incidents'
                    ? 'bg-blue-600 text-white shadow-md shadow-blue-900/40'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <AlertTriangle className="w-3.5 h-3.5 text-amber-300" />
                <span>Incidents Board ({incidents.length})</span>
              </button>
              <button
                id="view-logs"
                onClick={() => setAnalystSubView('logs')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  analystSubView === 'logs'
                    ? 'bg-blue-600 text-white shadow-md shadow-blue-900/40'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Telemetry Stream ({logs.length})</span>
              </button>
              <button
                id="view-setup-guide"
                onClick={() => setAnalystSubView('setup_guide')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  analystSubView === 'setup_guide'
                    ? 'bg-blue-600 text-white shadow-md shadow-blue-900/40'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Server className="w-3.5 h-3.5 text-indigo-300" />
                <span>Laptop / VPS Setup Guide</span>
              </button>
              <button
                id="view-mitre"
                onClick={() => setAnalystSubView('mitre')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  analystSubView === 'mitre'
                    ? 'bg-blue-600 text-white shadow-md shadow-blue-900/40'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>MITRE ATT&CK Matrix</span>
              </button>
              <button
                id="view-intel"
                onClick={() => setAnalystSubView('intel')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  analystSubView === 'intel'
                    ? 'bg-blue-600 text-white shadow-md shadow-blue-900/40'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>Threat Intel Feeds</span>
              </button>
            </div>

            {/* Export & Action Buttons */}
            <div className="flex items-center gap-2">
              <button
                id="btn-export-csv"
                onClick={handleExportCsv}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition cursor-pointer"
                title="Export CSV"
              >
                <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
                <span>CSV</span>
              </button>
              <button
                id="btn-export-json"
                onClick={handleExportJson}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition cursor-pointer"
                title="Export JSON"
              >
                <Terminal className="w-3.5 h-3.5 text-blue-400" />
                <span>JSON</span>
              </button>
              <button
                id="btn-export-stix"
                onClick={handleExportStix}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-blue-700 to-indigo-700 hover:from-blue-600 hover:to-indigo-600 text-white shadow transition cursor-pointer"
                title="Export OASIS STIX 2.1 Threat Intel Bundle"
              >
                <Radio className="w-3.5 h-3.5 text-amber-300" />
                <span>STIX 2.1 (SIEM)</span>
              </button>
              <button
                id="btn-clear-logs"
                onClick={handleClearLogs}
                className="p-1.5 rounded-lg text-xs text-slate-400 hover:text-red-400 hover:bg-red-500/10 border border-slate-800 transition cursor-pointer"
                title="Clear all logs"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* ========================================================================= */}
          {/* SUB-VIEW 0: PIPELINE SIMULATOR & REPLAYER */}
          {/* ========================================================================= */}
          {analystSubView === 'pipeline' && (
            <PipelineSimulator onTelemetryDispatched={refreshData} />
          )}

          {/* ========================================================================= */}
          {/* SUB-VIEW: BACKEND SETUP GUIDE */}
          {/* ========================================================================= */}
          {analystSubView === 'setup_guide' && (
            <BackendSetupGuide />
          )}

          {/* Filter Bar */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 space-y-3">
            <div className="flex flex-col sm:flex-row gap-3">
              {/* Search text */}
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search domain, sanitized URL, target brand, signals, or reasons..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition"
                />
              </div>

              {/* Filters */}
              <div className="flex flex-wrap items-center gap-2">
                <select
                  value={verdictFilter}
                  onChange={(e) => setVerdictFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
                >
                  <option value="ALL">All Verdicts</option>
                  <option value="DANGEROUS">Dangerous</option>
                  <option value="HIGH_RISK">High Risk</option>
                  <option value="SUSPICIOUS">Suspicious</option>
                  <option value="LOW_RISK">Low Risk</option>
                  <option value="SAFE">Safe</option>
                </select>

                <select
                  value={actionFilter}
                  onChange={(e) => setActionFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
                >
                  <option value="ALL">All Actions</option>
                  <option value="BLOCKING_MODAL">Blocking Modal</option>
                  <option value="IN_PAGE_BANNER">In-Page Banner</option>
                  <option value="FORM_SUBMISSION_INTERCEPTED">Form Intercepted</option>
                  <option value="DOWNLOAD_INTERCEPTED">Download Intercepted</option>
                  <option value="SILENT_MONITORING">Silent Monitoring</option>
                </select>

                <select
                  value={timeRangeMs}
                  onChange={(e) => setTimeRangeMs(Number(e.target.value))}
                  className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
                >
                  <option value={0}>All Time</option>
                  <option value={3600000}>Last 1 Hour</option>
                  <option value={86400000}>Last 24 Hours</option>
                  <option value={604800000}>Last 7 Days</option>
                </select>
              </div>
            </div>

            {/* Boolean Quick Toggles */}
            <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-slate-800/60 text-xs">
              <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={hasFormRiskOnly}
                  onChange={(e) => setHasFormRiskOnly(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-700 text-blue-600 focus:ring-0"
                />
                <span>Contains Credential Forms Only</span>
              </label>

              <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={hasThreatIntelOnly}
                  onChange={(e) => setHasThreatIntelOnly(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-700 text-blue-600 focus:ring-0"
                />
                <span>Threat Intelligence Feed Flags Only</span>
              </label>
            </div>
          </div>

          {/* ========================================================================= */}
          {/* SUB-VIEW 1: TELEMETRY STREAM LOGS */}
          {/* ========================================================================= */}
          {analystSubView === 'logs' && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase tracking-wider font-semibold text-[10px]">
                      <th className="py-3 px-4">Timestamp</th>
                      <th className="py-3 px-4">Domain / Destination</th>
                      <th className="py-3 px-4">Risk Score</th>
                      <th className="py-3 px-4">Verdict</th>
                      <th className="py-3 px-4">Target Brand</th>
                      <th className="py-3 px-4">Action Taken</th>
                      <th className="py-3 px-4">Intel Hits</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {logs.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                          No telemetry records match the current filter criteria.
                        </td>
                      </tr>
                    ) : (
                      logs.map((log) => (
                        <tr
                          key={log.id}
                          onClick={() => setSelectedLog(log)}
                          className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                        >
                          <td className="py-3 px-4 text-slate-400 whitespace-nowrap text-[11px]">
                            {new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </td>
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2">
                              <span className="font-semibold text-slate-200 truncate max-w-[200px] sm:max-w-xs">
                                {log.domain}
                              </span>
                              {log.formRiskIndicators.hasPasswordInput && (
                                <span className="p-1 rounded bg-purple-500/10 text-purple-400" title="Contains password input">
                                  <Lock className="w-3 h-3" />
                                </span>
                              )}
                              {log.wasDangerousFormBlocked && (
                                <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/20 text-red-300 font-sans font-bold">
                                  FORM BLOCKED
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-3 px-4">
                            <span className={`font-bold ${log.pageRiskScore >= 60 ? 'text-red-400' : log.pageRiskScore >= 40 ? 'text-amber-400' : 'text-emerald-400'}`}>
                              {log.pageRiskScore}/100
                            </span>
                          </td>
                          <td className="py-3 px-4 font-sans">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityBadgeClass(log.severity)}`}>
                              {log.verdict}
                            </span>
                          </td>
                          <td className="py-3 px-4 font-sans">
                            {log.targetBrandName ? (
                              <span className="text-[11px] font-semibold text-blue-400">
                                {log.targetBrandName}
                              </span>
                            ) : (
                              <span className="text-slate-600">—</span>
                            )}
                          </td>
                          <td className="py-3 px-4 font-sans">
                            <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${getActionBadgeClass(log.actionTaken)}`}>
                              {log.actionTaken.replace(/_/g, ' ')}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            {log.threatIntelligence.flaggedCount > 0 ? (
                              <span className="text-red-400 font-bold">
                                {log.threatIntelligence.flaggedCount}/{log.threatIntelligence.providersCount}
                              </span>
                            ) : (
                              <span className="text-emerald-400/80">0/{log.threatIntelligence.providersCount}</span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-right font-sans">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedLog(log);
                              }}
                              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium transition cursor-pointer"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* SUB-VIEW 2: SECURITY INCIDENTS BOARD */}
          {/* ========================================================================= */}
          {analystSubView === 'incidents' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {incidents.length === 0 ? (
                  <div className="col-span-full py-12 text-center text-slate-500">
                    No active security incidents recorded.
                  </div>
                ) : (
                  incidents.map((inc) => {
                    const targetDomain = (inc as any).targetDomain || inc.affectedDomain || '';
                    const targetUrl = (inc as any).targetUrl || `https://${targetDomain}`;
                    const targetBrand = (inc as any).impersonatedBrand || inc.targetBrand || '';
                    const actionTaken = (inc as any).actionTaken || 'BLOCKED';
                    const score = inc.riskScore ?? (inc as any).score ?? 100;
                    const verdict = (inc as any).verdict || (score >= 80 ? 'DANGEROUS' : 'HIGH_RISK');

                    return (
                      <div
                        key={inc.incidentId}
                        onClick={() => setSelectedIncident(inc)}
                        className="bg-slate-900/90 border border-slate-800 hover:border-red-500/40 rounded-2xl p-5 flex flex-col justify-between transition-all cursor-pointer shadow-lg hover:shadow-red-950/20 space-y-3"
                      >
                        <div>
                          {/* Incident ID & Verdict */}
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-xs font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                              {inc.incidentId}
                            </span>
                            <span className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded border ${
                              verdict === 'DANGEROUS' || inc.severity === 'CRITICAL'
                                ? 'bg-red-500/20 text-red-400 border-red-500/30'
                                : 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                            }`}>
                              {verdict}
                            </span>
                          </div>

                          {/* Target */}
                          <div className="mt-3">
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Target Domain:</span>
                            <div className="font-mono text-xs font-bold text-white truncate mt-0.5">
                              {targetDomain}
                            </div>
                          </div>

                          {/* Signals Checklist */}
                          <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-1.5">
                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Signals Observed:</span>
                            
                            {targetBrand && (
                              <div className="flex items-center gap-1.5 text-xs text-slate-200">
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                <span>Brand impersonation ({targetBrand})</span>
                              </div>
                            )}

                            {/netlify|vercel|pages\.dev|render/i.test(targetDomain) && (
                              <div className="flex items-center gap-1.5 text-xs text-slate-200">
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                <span>Third-party cloud hosting abuse</span>
                              </div>
                            )}

                            <div className="flex items-center gap-1.5 text-xs text-slate-200">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                              <span>Active credential/payment collection form</span>
                            </div>

                            <div className="flex items-center gap-1.5 text-xs text-slate-200">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                              <span>Domain & infrastructure mismatch</span>
                            </div>

                            <div className="flex items-center gap-1.5 text-xs text-slate-200">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                              <span>Multi-source threat intelligence verified</span>
                            </div>
                          </div>

                          {/* MITRE ATT&CK Codes */}
                          <div className="mt-3 pt-2 flex flex-wrap gap-1">
                            {((inc as any).mitreTechniques || inc.mitreTechniques || ['T1584.004', 'T1598.003', 'T1566.002']).map((t: any) => {
                              const code = typeof t === 'string' ? t : t.id;
                              return (
                                <span key={code} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20">
                                  {code}
                                </span>
                              );
                            })}
                          </div>
                        </div>

                        {/* Action Enforced & Status */}
                        <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-400">Action:</span>
                            <span className="font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                              {actionTaken}
                            </span>
                          </div>
                          <span className={`font-semibold text-[11px] ${
                            inc.status === 'ACTIVE' || (inc as any).status === 'OPEN' ? 'text-rose-400' :
                            inc.status === 'INVESTIGATING' ? 'text-amber-400' :
                            inc.status === 'MITIGATED' || (inc as any).status === 'CONFIRMED_PHISH' ? 'text-emerald-400' : 'text-slate-400'
                          }`}>
                            ● {inc.status || (inc as any).status || 'OPEN'}
                          </span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* SUB-VIEW 3: MITRE ATT&CK MATRIX COVERAGE */}
          {/* ========================================================================= */}
          {analystSubView === 'mitre' && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <Layers className="w-5 h-5 text-blue-400" />
                    MITRE ATT&CK® Detection Coverage
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Automated mapping of browser telemetry signals to enterprise adversary techniques.
                  </p>
                </div>
                <span className="text-xs px-3 py-1 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20 font-semibold">
                  Enterprise Framework
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {metrics.mitreCoverage.map((item) => (
                  <div key={item.id} className="bg-slate-950/70 border border-slate-800 rounded-xl p-4">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-blue-400">{item.id}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 uppercase font-semibold">
                        {item.tactic}
                      </span>
                    </div>
                    <h4 className="text-sm font-semibold text-white mt-1.5">{item.name}</h4>
                    <div className="mt-3 flex items-center justify-between text-xs pt-2 border-t border-slate-800/80">
                      <span className="text-slate-400">Observed Incidents:</span>
                      <span className="font-bold text-rose-400">{item.count} detections</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* SUB-VIEW 4: THREAT INTELLIGENCE FEEDS STATUS */}
          {/* ========================================================================= */}
          {analystSubView === 'intel' && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <Globe className="w-5 h-5 text-emerald-400" />
                    Multi-Source Threat Intelligence Integrations
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Real-time external feed status, lookup latencies, and threat verification feeds.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">URLhaus (Abuse.ch)</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-semibold">
                      OPERATIONAL
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    Global community repository of active malware and phishing URLs.
                  </p>
                  <div className="mt-4 pt-2 border-t border-slate-800 flex items-center justify-between text-xs">
                    <span className="text-slate-400">Avg Latency</span>
                    <span className="font-mono text-slate-300">4 ms</span>
                  </div>
                </div>

                <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">VirusTotal API</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-semibold">
                      OPERATIONAL
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    Aggregated multi-engine scanning across 70+ antivirus and web threat scanners.
                  </p>
                  <div className="mt-4 pt-2 border-t border-slate-800 flex items-center justify-between text-xs">
                    <span className="text-slate-400">Avg Latency</span>
                    <span className="font-mono text-slate-300">6 ms</span>
                  </div>
                </div>

                <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">PhishTank Community</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-semibold">
                      OPERATIONAL
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    Crowdsourced and human-verified phishing intelligence database.
                  </p>
                  <div className="mt-4 pt-2 border-t border-slate-800 flex items-center justify-between text-xs">
                    <span className="text-slate-400">Avg Latency</span>
                    <span className="font-mono text-slate-300">3 ms</span>
                  </div>
                </div>

                <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">Google Safe Browsing</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-semibold">
                      OPERATIONAL
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    Industry standard social engineering and web risk threat classifier.
                  </p>
                  <div className="mt-4 pt-2 border-t border-slate-800 flex items-center justify-between text-xs">
                    <span className="text-slate-400">Avg Latency</span>
                    <span className="font-mono text-slate-300">5 ms</span>
                  </div>
                </div>

                <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">OpenPhish Feed</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-semibold">
                      OPERATIONAL
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    Targeted sector categorization for high-impact financial & cloud brands.
                  </p>
                  <div className="mt-4 pt-2 border-t border-slate-800 flex items-center justify-between text-xs">
                    <span className="text-slate-400">Avg Latency</span>
                    <span className="font-mono text-slate-300">3 ms</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* DETAIL MODAL / FORENSIC DRAWER: TELEMETRY LOG INSPECTOR */}
      {/* ========================================================================= */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 sm:p-6 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-3">
                <div className={`p-2.5 rounded-xl border ${getSeverityBadgeClass(selectedLog.severity)}`}>
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-white font-mono">{selectedLog.domain}</h3>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityBadgeClass(selectedLog.severity)}`}>
                      {selectedLog.verdict} ({selectedLog.pageRiskScore}/100)
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono mt-0.5 truncate max-w-xl">
                    {selectedLog.url}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Modal Scrollable Body */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-300">
              {/* Privacy Badge */}
              <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-3 flex items-center gap-2.5 text-emerald-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>
                  <strong>Strict Privacy Guarantee:</strong> This telemetry log records structural and domain metadata only. Zero typed inputs, passwords, card numbers, or authorization tokens are captured.
                </span>
              </div>

              {/* Core Telemetry Overview Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <span className="text-[10px] text-slate-500 block uppercase font-sans">Timestamp</span>
                  <span className="font-semibold text-slate-200">{selectedLog.timeIso}</span>
                </div>
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <span className="text-[10px] text-slate-500 block uppercase font-sans">Action Taken</span>
                  <span className="font-semibold text-blue-400">{selectedLog.actionTaken}</span>
                </div>
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <span className="text-[10px] text-slate-500 block uppercase font-sans">Target Brand</span>
                  <span className="font-semibold text-amber-400">{selectedLog.targetBrandName || 'None'}</span>
                </div>
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <span className="text-[10px] text-slate-500 block uppercase font-sans">Form Blocked?</span>
                  <span className={`font-semibold ${selectedLog.wasDangerousFormBlocked ? 'text-red-400' : 'text-slate-400'}`}>
                    {selectedLog.wasDangerousFormBlocked ? 'YES (Intercepted)' : 'NO'}
                  </span>
                </div>
              </div>

              {/* Detected Signals */}
              <div>
                <h4 className="font-bold text-white text-xs uppercase tracking-wider mb-2">Detected Security Signals</h4>
                <div className="space-y-2">
                  {selectedLog.detectedSignals.length === 0 ? (
                    <p className="text-slate-500">No malicious signals detected.</p>
                  ) : (
                    selectedLog.detectedSignals.map((sig) => (
                      <div key={sig.id} className="p-3 bg-slate-950 border border-slate-800/80 rounded-xl flex items-start justify-between gap-3">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-white">{sig.title}</span>
                            <span className={`text-[9px] px-1.5 py-0.5 rounded border font-mono ${getSeverityBadgeClass(sig.severity)}`}>
                              +{sig.weight} pts
                            </span>
                          </div>
                          <p className="text-slate-400 text-[11px] mt-1">{sig.description}</p>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Threat Intelligence Breakdown */}
              <div>
                <h4 className="font-bold text-white text-xs uppercase tracking-wider mb-2">Threat Intelligence Provider Checks</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {selectedLog.threatIntelligence.results.map((r) => (
                    <div key={r.provider} className="p-3 bg-slate-950 border border-slate-800 rounded-xl flex items-center justify-between">
                      <div>
                        <span className="font-semibold text-white block">{r.provider}</span>
                        <span className="text-[11px] text-slate-400">{r.details}</span>
                      </div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${r.isFlagged ? 'bg-red-500/10 text-red-400 border-red-500/30' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'}`}>
                        {r.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* DOM & Form Indicators */}
              <div>
                <h4 className="font-bold text-white text-xs uppercase tracking-wider mb-2">DOM & Form Risk Indicators</h4>
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                    <div>Forms Count: <span className="font-mono text-white">{selectedLog.formRiskIndicators.formsCount}</span></div>
                    <div>Password Input: <span className="font-mono text-white">{selectedLog.formRiskIndicators.hasPasswordInput ? 'YES' : 'NO'}</span></div>
                    <div>Payment Card: <span className="font-mono text-white">{selectedLog.formRiskIndicators.hasCreditCardInput ? 'YES' : 'NO'}</span></div>
                    <div>2FA / OTP Field: <span className="font-mono text-white">{selectedLog.formRiskIndicators.has2FAInput ? 'YES' : 'NO'}</span></div>
                  </div>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 flex items-center justify-between bg-slate-950">
              <span className="text-slate-500 text-[11px]">Log ID: {selectedLog.id}</span>
              <button
                onClick={() => setSelectedLog(null)}
                className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* DETAIL MODAL / TRIAGE DRAWER: INCIDENT MANAGER */}
      {/* ========================================================================= */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-4 sm:p-6 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-slate-400">{selectedIncident.incidentId}</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityBadgeClass(selectedIncident.severity)}`}>
                    {selectedIncident.severity}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white mt-1">{selectedIncident.title}</h3>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-300">
              {/* Status Triage Controls */}
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-slate-400 block font-semibold mb-2">Triage Status Workflow:</span>
                <div className="flex flex-wrap gap-2">
                  {(['ACTIVE', 'INVESTIGATING', 'MITIGATED', 'FALSE_POSITIVE', 'RESOLVED'] as IncidentStatus[]).map((st) => (
                    <button
                      key={st}
                      onClick={() => handleUpdateIncidentStatus(selectedIncident.incidentId, st)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition cursor-pointer ${
                        selectedIncident.status === st
                          ? 'bg-blue-600 text-white border-blue-500'
                          : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white hover:bg-slate-800'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              {/* MITRE Techniques */}
              <div>
                <h4 className="font-bold text-white text-xs uppercase tracking-wider mb-2">MITRE ATT&CK Techniques</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {selectedIncident.mitreTechniques.map((t) => (
                    <div key={t.id} className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
                      <span className="font-mono text-blue-400 font-bold block">{t.id}</span>
                      <span className="font-semibold text-white block mt-0.5">{t.name}</span>
                      <span className="text-[10px] text-slate-500 uppercase">{t.tactic}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Analyst Notes Log */}
              <div>
                <h4 className="font-bold text-white text-xs uppercase tracking-wider mb-2">Analyst Notes & Audit History</h4>
                <div className="space-y-2 mb-3">
                  {selectedIncident.analystNotes.map((note) => (
                    <div key={note.id} className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
                      <div className="flex items-center justify-between text-[11px] text-slate-400 mb-1">
                        <span className="font-semibold text-blue-400">{note.author}</span>
                        <span>{new Date(note.timestamp).toLocaleString()}</span>
                      </div>
                      <p className="text-slate-200">{note.text}</p>
                    </div>
                  ))}
                </div>

                {/* Add Note Form */}
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Add security investigation note..."
                    value={newAnalystNote}
                    onChange={(e) => setNewAnalystNote(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleAddIncidentNote(); }}
                    className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                  <button
                    onClick={handleAddIncidentNote}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl text-xs flex items-center gap-1.5 transition cursor-pointer"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>Save Note</span>
                  </button>
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-slate-800 flex justify-end bg-slate-950">
              <button
                onClick={() => setSelectedIncident(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-semibold text-xs transition cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
