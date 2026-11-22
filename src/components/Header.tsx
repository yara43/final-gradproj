import React from 'react';
import { Shield, Download, Play, Code, Eye, RefreshCw, Database } from 'lucide-react';
import { generateExtensionZipBlob } from '../utils/extensionFiles';

interface HeaderProps {
  activeTab: 'inspector' | 'tests' | 'extension' | 'preview' | 'logs';
  setActiveTab: (tab: 'inspector' | 'tests' | 'extension' | 'preview' | 'logs') => void;
  onQuickScan: () => void;
}

export const Header: React.FC<HeaderProps> = ({ activeTab, setActiveTab, onQuickScan }) => {
  const [downloading, setDownloading] = React.useState(false);

  const handleDownloadZip = async () => {
    try {
      setDownloading(true);
      const blob = await generateExtensionZipBlob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'phishguard-extension-v3.zip';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to generate extension zip:', err);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand identity */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 via-indigo-600 to-emerald-500 p-[1px] flex items-center justify-center shadow-lg shadow-blue-500/10">
            <div className="w-full h-full bg-slate-950 rounded-xl flex items-center justify-center">
              <Shield className="w-5 h-5 text-blue-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-base tracking-tight text-white">PhishGuard</span>
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                Manifest V3
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Real-Time Browser Phishing Detection Engine
            </p>
          </div>
        </div>

        {/* View switchers */}
        <nav className="flex items-center gap-1 bg-slate-900/90 p-1 rounded-xl border border-slate-800">
          <button
            id="tab-inspector"
            onClick={() => setActiveTab('inspector')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              activeTab === 'inspector'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Inspector</span>
          </button>

          <button
            id="tab-logs"
            onClick={() => setActiveTab('logs')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              activeTab === 'logs'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            <span>Security Logs</span>
          </button>

          <button
            id="tab-tests"
            onClick={() => setActiveTab('tests')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              activeTab === 'tests'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Play className="w-3.5 h-3.5" />
            <span>Test Suite</span>
          </button>

          <button
            id="tab-preview"
            onClick={() => setActiveTab('preview')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              activeTab === 'preview'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Eye className="w-3.5 h-3.5" />
            <span>Extension Preview</span>
          </button>

          <button
            id="tab-extension"
            onClick={() => setActiveTab('extension')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              activeTab === 'extension'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Code className="w-3.5 h-3.5" />
            <span>Extension Code</span>
          </button>
        </nav>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            id="btn-download-zip"
            onClick={handleDownloadZip}
            disabled={downloading}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-md shadow-emerald-900/20 transition-all cursor-pointer"
          >
            {downloading ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Download className="w-3.5 h-3.5" />
            )}
            <span>Download Unpacked (.ZIP)</span>
          </button>
        </div>
      </div>
    </header>
  );
};
