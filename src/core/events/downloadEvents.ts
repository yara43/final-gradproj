/**
 * PhishGuard Download Security Event Analyzer
 */

import { DownloadSecurityEvent, ThreatSeverity } from './eventTypes';

export const EXECUTABLE_EXTENSIONS = [
  'exe', 'msi', 'bat', 'cmd', 'scr', 'vbs', 'js', 'jar', 'apk',
  'iso', 'img', 'vhd', 'hta', 'ps1', 'wsf', 'com', 'pif'
];

export interface RawDownloadContext {
  tabId: number;
  downloadId: number;
  url: string;
  filename: string;
  originUrl: string;
  originRiskScore: number;
}

export function createDownloadSecurityEvent(ctx: RawDownloadContext): DownloadSecurityEvent {
  const parts = ctx.filename.split('.');
  const ext = parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
  const isExecutable = EXECUTABLE_EXTENSIONS.includes(ext);

  let originOrigin = '';
  try {
    originOrigin = new URL(ctx.originUrl.startsWith('http') ? ctx.originUrl : 'https://' + ctx.originUrl).origin;
  } catch {
    originOrigin = ctx.originUrl;
  }

  let severity: ThreatSeverity = 'LOW';
  let title = 'File Download Triggered';
  let description = `Download initiated for ${ctx.filename}.`;

  if (isExecutable && ctx.originRiskScore >= 60) {
    severity = 'CRITICAL';
    title = 'Dangerous Executable Download on High-Risk Site';
    description = `An executable file (${ctx.filename}) was triggered from a high-risk or suspicious webpage (Risk: ${ctx.originRiskScore}/100).`;
  } else if (isExecutable) {
    severity = 'MEDIUM';
    title = 'Executable File Download';
    description = `Binary executable (${ctx.filename}) download initiated.`;
  }

  return {
    id: `dl_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: Date.now(),
    tabId: ctx.tabId,
    pageUrl: ctx.originUrl,
    pageOrigin: originOrigin,
    type: 'DOWNLOAD_TRIGGERED',
    severity,
    title,
    description,
    downloadId: ctx.downloadId,
    filename: ctx.filename,
    fileExtension: ext,
    downloadUrl: ctx.url,
    isExecutable,
    originRiskScore: ctx.originRiskScore,
    evidence: {
      filename: ctx.filename,
      fileExtension: ext,
      isExecutable,
      originRiskScore: ctx.originRiskScore
    }
  };
}
