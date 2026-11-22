import React, { useState } from 'react';
import { Header } from './components/Header';
import { UrlInspector } from './components/UrlInspector';
import { TestSuiteRunner } from './components/TestSuiteRunner';
import { ExtensionSimulator } from './components/ExtensionSimulator';
import { FileViewer } from './components/FileViewer';
import { SettingsPanel } from './components/SettingsPanel';
import { SecurityDashboard } from './components/SecurityDashboard/SecurityDashboard';
import { DEFAULT_SETTINGS } from './config/rules';
import { ExtensionSettings } from './types';
import { Shield, Sparkles, SlidersHorizontal, ArrowUpRight } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<'inspector' | 'tests' | 'extension' | 'preview' | 'logs'>('inspector');
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_SETTINGS);
  const [showSettingsDrawer, setShowSettingsDrawer] = useState(false);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-blue-600 selection:text-white flex flex-col">
      {/* Primary Top Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onQuickScan={() => setActiveTab('inspector')}
      />

      {/* Secondary Bar / Breadcrumbs & Settings Toggle */}
      <div className="border-b border-slate-900 bg-slate-950/60">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2.5 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2 text-slate-400">
            <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="font-mono text-slate-300">PhishGuard Engine v1.0.0</span>
            <span>•</span>
            <span className="text-slate-400">Deterministic Multi-Signal Heuristics</span>
            <span>•</span>
            <span className="text-slate-400">Sub-10ms Privacy Evaluation</span>
          </div>

          <button
            onClick={() => setShowSettingsDrawer(!showSettingsDrawer)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
              showSettingsDrawer
                ? 'bg-blue-600/20 text-blue-300 border border-blue-500/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            <span>{showSettingsDrawer ? 'Close Engine Config' : 'Configure Engine'}</span>
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {showSettingsDrawer ? (
          <SettingsPanel settings={settings} setSettings={setSettings} />
        ) : (
          <>
            {activeTab === 'inspector' && (
              <UrlInspector
                settings={settings}
                setSettings={setSettings}
                onOpenPreviewTab={() => setActiveTab('preview')}
              />
            )}

            {activeTab === 'logs' && (
              <SecurityDashboard
                onInspectUrl={(url) => {
                  setActiveTab('inspector');
                }}
              />
            )}

            {activeTab === 'tests' && (
              <TestSuiteRunner />
            )}

            {activeTab === 'preview' && (
              <ExtensionSimulator />
            )}

            {activeTab === 'extension' && (
              <FileViewer />
            )}
          </>
        )}
      </main>

      {/* Global Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-blue-500" />
            <span className="font-semibold text-slate-400">PhishGuard Security Suite</span>
            <span>— Chrome Manifest V3 Browser Protection</span>
          </div>
          <div className="flex items-center gap-4">
            <span>Zero Remote Exfiltration</span>
            <span>•</span>
            <span>Zero Credential Access</span>
            <span>•</span>
            <span>100% Client-Side Evaluation</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
