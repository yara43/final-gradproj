import { analyzePageSecurity } from '../engine/riskScoring.js';
import { DEFAULT_SETTINGS } from '../config/rules.js';
import { globalEventStore } from '../events/eventStore.js';
import { createNetworkSecurityEvent } from '../events/networkEvents.js';
import { createPageBrandingEvent } from '../events/pageEvents.js';
import { parseHttpUrl } from '../engine/formDestinations.js';
import { createNavigationSecurityEvent } from '../events/navigationEvents.js';
import { createDownloadSecurityEvent } from '../events/downloadEvents.js';
import { correlateSecurityEvents } from '../events/eventCorrelator.js';

// In-memory cache with MV3 chrome.storage.session integration
const tabScanResults = new Map();
const tabRedirectHistory = new Map();
const tabDownloadContexts = new Map();
const tabDomMetadata = new Map();
const dismissedWarnings = new Set(); // Temporarily bypassed domains in current session

/**
 * Initialize Default Storage Configuration on Install
 */
chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get(['settings', 'history']);
  if (!existing.settings) {
    await chrome.storage.local.set({
      settings: DEFAULT_SETTINGS,
      history: []
    });
  }
});

/**
 * Helper to retrieve current settings
 */
async function getSettings() {
  const data = await chrome.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...(data.settings || {}) };
}

/**
 * Session storage helpers to survive MV3 Service Worker dormancy
 */
async function getSessionData(key) {
  try {
    if (chrome.storage && chrome.storage.session) {
      const data = await chrome.storage.session.get(key);
      return data[key];
    }
  } catch {
    // storage.session unavailable, fall back to memory
  }
  return null;
}

async function setSessionData(key, value) {
  try {
    if (chrome.storage && chrome.storage.session) {
      await chrome.storage.session.set({ [key]: value });
    }
  } catch {
    // ignore
  }
}

/**
 * Update Extension Badge based on 5-Tier Security Verdict
 * SAFE (0-19), LOW_RISK (20-39), SUSPICIOUS (40-59), HIGH_RISK (60-79), DANGEROUS (80-100)
 */
function updateBadge(tabId, verdict, score) {
  if (!tabId || tabId < 0) return;

  let badgeText = '';
  let badgeColor = '#10B981'; // Green

  if (verdict === 'DANGEROUS') {
    badgeText = '!';
    badgeColor = '#DC2626'; // Deep Red
  } else if (verdict === 'HIGH_RISK') {
    badgeText = `${score}`;
    badgeColor = '#EF4444'; // Red
  } else if (verdict === 'SUSPICIOUS') {
    badgeText = `${score}`;
    badgeColor = '#F59E0B'; // Amber
  } else if (verdict === 'LOW_RISK') {
    badgeText = '';
    badgeColor = '#3B82F6'; // Blue
  } else {
    // SAFE: Quiet by default
    badgeText = '';
    badgeColor = '#10B981'; // Green
  }

  try {
    chrome.action.setBadgeText({ tabId, text: badgeText });
    chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
  } catch {
    // Tab may have closed
  }
}

/**
 * Main Analysis Coordinator for a given Tab URL
 */
async function performTabScan(tabId, url, formMetadata = null, socialMeta = null) {
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:') || url.startsWith('edge://')) {
    return null;
  }

  const settings = await getSettings();
  const redirectData = tabRedirectHistory.get(tabId) || {
    initialUrl: url,
    finalUrl: url,
    hops: [{ url, timestamp: Date.now() }],
    hopCount: 1
  };

  const downloadContext = tabDownloadContexts.get(tabId) || null;

  const cached = tabDomMetadata.get(tabId);
  if (!formMetadata && cached?.url === url) {
    formMetadata = cached.formMetadata;
    socialMeta = cached.socialMeta;
  }

  const tabEvents = globalEventStore.getTabEvents(tabId);
  if (formMetadata && cached?.url === url) {
    const observedDestinations = tabEvents.filter(event =>
      event.type === 'CREDENTIAL_SUBMISSION_PATTERN' && event.documentId === cached.documentId
    ).map(event => event.destinationUrl);
    formMetadata = { ...formMetadata, observedDestinations };
  }

  const analysis = analyzePageSecurity(url, formMetadata, redirectData, settings, socialMeta, downloadContext);
  const correlated = correlateSecurityEvents({
    tabId, url, domain: analysis.domain,
    events: tabEvents.filter(event => event.type !== 'CREDENTIAL_SUBMISSION_PATTERN'),
    ...analysis.features?.reputation
  });

  if (settings.protectionEnabled && correlated.score > analysis.score) {
    analysis.score = correlated.score;
    analysis.verdict = correlated.verdict;
    analysis.severity = correlated.severity;
  }

  tabScanResults.set(tabId, analysis);
  await setSessionData(`tab_${tabId}`, analysis);

  // Update extension badge
  updateBadge(tabId, analysis.verdict, analysis.score);

  // Save to local scan history (privacy-safe: domain, score, timestamp, top signals only)
  await recordScanHistory(analysis);

  // STEP 2: Send structured privacy-safe telemetry event to VPS Backend
  dispatchTelemetryToVPS(url, analysis, formMetadata, redirectData, settings).then(serverVerdict => {
    if (serverVerdict && serverVerdict.incidentId) {
      analysis.incidentId = serverVerdict.incidentId;
      if (serverVerdict.score > analysis.score) {
        analysis.score = serverVerdict.score;
        analysis.verdict = serverVerdict.verdict;
        analysis.severity = serverVerdict.severity;
        updateBadge(tabId, analysis.verdict, analysis.score);
      }
    }
  }).catch(() => {
    // Non-blocking offline fallback
  });

  // Check if warning interstitial is required
  const sessionDismissed = await getSessionData('dismissed_domains') || [];
  const isDismissed = dismissedWarnings.has(analysis.domain) || sessionDismissed.includes(analysis.domain.toLowerCase());
  if (analysis.score >= settings.warningThreshold && !isDismissed && settings.protectionEnabled) {
    const warningUrl = chrome.runtime.getURL(
      `warning/warning.html?url=${encodeURIComponent(url)}&score=${analysis.score}&verdict=${analysis.verdict}&domain=${encodeURIComponent(analysis.domain)}`
    );

    // Notify active content script to display non-destructive in-page banner
    try {
      chrome.tabs.sendMessage(tabId, {
        type: 'PHISHGUARD_SHOW_BANNER',
        analysis
      }).catch(() => {});
    } catch {
      // Content script may not be initialized yet
    }

    // If score meets or exceeds blockThreshold, navigate to warning interstitial
    // If score meets or exceeds blockThreshold, navigate to warning interstitial
    if (analysis.score >= settings.blockThreshold) {
      await setSessionData(`warning_${tabId}`, {
        ...analysis,
        url
      });

      chrome.tabs.update(tabId, { url: warningUrl });
    }
  }

  return analysis;
}
/**
 * STEP 2: Dispatches structured, privacy-preserving observation event to PhishGuard VPS API
 * 
 * STRICT PRIVACY CONTRACT:
 * - NO passwords
 * - NO credit card numbers
 * - NO cookies or tokens
 * - NO raw form input values
 * - NO typed request bodies
 */
async function dispatchTelemetryToVPS(url, analysis, formMetadata, redirectData, settings) {
  try {
    const endpoint = settings.telemetryEndpoint || '/api/telemetry';
    
        const payload = {
      event_type: 'page_analysis',
      url: parseHttpUrl(url)?.origin ?? '',
      domain: analysis.domain,
      title: formMetadata?.pageTitle || '',
      forms: {
        password: !!formMetadata?.hasPasswordInput,
        payment: !!formMetadata?.hasCreditCardInput,
        otp: !!formMetadata?.has2FAInput,
        ssn: !!formMetadata?.hasSsnInput
      },
      cross_origin_forms: (formMetadata?.suspiciousForms || []).map(f => ({
       action: parseHttpUrl(f.action)?.origin ?? '',
        method: f.method,
        is_cross_origin: f.isCrossOrigin,
        has_password: f.hasPasswordField
      })),
      redirects: (redirectData?.hops || [])
  .map(h => parseHttpUrl(h.url)?.origin)
  .filter(Boolean),
      detected_brands: analysis.targetBrand ? [analysis.targetBrand.name] : [],
      timestamp: new Date().toISOString()
    };

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-PhishGuard-Agent': 'MV3-Extension',
        'X-Extension-Version': '1.0.0'
      },
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    // Graceful offline failover
  }
  return null;
}

/**
 * Record non-sensitive metadata in local scan history
 */
async function recordScanHistory(analysis) {
  try {
    const data = await chrome.storage.local.get(['history', 'settings']);
    const history = data.history || [];
    const limit = data.settings?.scanHistoryLimit || 100;

    const topSignal = analysis.signals.length > 0 ? analysis.signals[0].title : 'No risks detected';

    const newItem = {
      id: `${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: analysis.timestamp,
      url: analysis.url,
      domain: analysis.domain,
      score: analysis.score,
      severity: analysis.severity,
      verdict: analysis.verdict,
      topSignal,
      reasons: analysis.reasons.slice(0, 2)
    };

    // Filter duplicates of same domain within recent window
    const updated = [newItem, ...history.filter(h => h.domain !== analysis.domain)].slice(0, limit);
    await chrome.storage.local.set({ history: updated });
  } catch (err) {
    console.error('[PhishGuard] Failed to update scan history:', err);
  }
}

/**
 * Real-Time Network Request Observation via Chrome WebRequest API
 * Privacy-first: Records ONLY method, URL target domain, and initiator origin.
 * NEVER captures request headers, bodies, cookies, or credentials.
 */
if (chrome.webRequest && chrome.webRequest.onBeforeRequest) {
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (details.tabId < 0 || details.frameId !== 0 || !details.documentId) return;
      if (!['POST', 'PUT', 'PATCH'].includes(details.method)) return;

      const context = tabDomMetadata.get(details.tabId);
      if (!context || context.documentId !== details.documentId ||
          !context.formMetadata.suspiciousForms?.some(form => form.hasPasswordField)) return;

      const page = parseHttpUrl(context.url);
      const destination = parseHttpUrl(details.url);
      if (!page || !destination || details.initiator !== page.origin) return;

      const event = createNetworkSecurityEvent({
        tabId: details.tabId,
        frameId: details.frameId,
        documentId: details.documentId,
        pageUrl: page.origin,
        requestUrl: destination.origin,
        method: details.method,
        type: details.type,
        timeStamp: details.timeStamp
      }, true);

      if (!event.sensitiveSubmissionPattern) return;
      const alreadyObserved = globalEventStore.getTabEvents(details.tabId).some(previous =>
        previous.documentId === event.documentId && previous.type === event.type &&
        previous.destinationUrl === event.destinationUrl && previous.method === event.method
      );
      if (alreadyObserved) return;
      globalEventStore.recordEvent(event);
      performTabScan(details.tabId, context.url).catch(() => {});

    },
    { urls: ['http://*/*', 'https://*/*'], types: ['xmlhttprequest'] }
  );
}

/**
 * Navigation & Redirect Tracking via Chrome WebNavigation API
 */
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // Top-level frame only

  const tabId = details.tabId;
  tabDomMetadata.delete(tabId);
  const existingHistory = tabRedirectHistory.get(tabId);

  if (!existingHistory) {
    tabRedirectHistory.set(tabId, {
      initialUrl: details.url,
      finalUrl: details.url,
      hops: [{ url: details.url, timestamp: Date.now() }],
      hopCount: 1,
      lastUpdated: Date.now()
    });
  }
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  
  const tabId = details.tabId;
  const isRedirect = details.transitionQualifiers && (
    details.transitionQualifiers.includes('server_redirect') ||
    details.transitionQualifiers.includes('client_redirect')
  );

  let history = tabRedirectHistory.get(tabId);
  if (isRedirect && history) {
    history.hops.push({ url: details.url, timestamp: Date.now() });
    history.hopCount = history.hops.length;
    history.finalUrl = details.url;
    history.lastUpdated = Date.now();
  } else {
    // Fresh user navigation
    history = {
      initialUrl: details.url,
      finalUrl: details.url,
      hops: [{ url: details.url, timestamp: Date.now() }],
      hopCount: 1,
      lastUpdated: Date.now()
    };
    tabRedirectHistory.set(tabId, history);
    globalEventStore.clearTab(tabId);
  }

  const navEvent = createNavigationSecurityEvent({ tabId, url: details.url }, history.hops.map(h => h.url));
  if (navEvent) {
    globalEventStore.recordEvent(navEvent);
  }

  performTabScan(details.tabId, details.url);
});

/**
 * Download Security Context Monitoring (Chrome Downloads API)
 */
if (chrome.downloads && chrome.downloads.onCreated) {
  chrome.downloads.onCreated.addListener(async (downloadItem) => {
    try {
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (activeTab && activeTab.id) {
        const currentAnalysis = tabScanResults.get(activeTab.id);
        const originRiskScore = currentAnalysis ? currentAnalysis.score : 0;
        const originVerdict = currentAnalysis ? currentAnalysis.verdict : 'SAFE';

        const filename = downloadItem.filename || downloadItem.url.split('/').pop() || 'download';
        const fileExtension = filename.includes('.') ? filename.split('.').pop() : '';

        const downloadContext = {
          downloadId: downloadItem.id,
          url: downloadItem.url,
          filename,
          fileExtension,
          originUrl: activeTab.url || downloadItem.referrer || '',
          originRiskScore,
          originVerdict,
          isDangerousOrigin: originRiskScore >= 60,
          isExecutable: ['exe', 'msi', 'scr', 'bat', 'iso', 'apk', 'vbs', 'ps1'].includes(fileExtension.toLowerCase()),
          timestamp: Date.now()
        };

        tabDownloadContexts.set(activeTab.id, downloadContext);

        const dlEvent = createDownloadSecurityEvent({ tabId: activeTab.id, ...downloadContext });
        if (dlEvent) {
          globalEventStore.recordEvent(dlEvent);
        }

        // If download initiated from high risk origin, re-evaluate tab score and badge
        if (downloadContext.isDangerousOrigin && currentAnalysis) {
          performTabScan(activeTab.id, activeTab.url, currentAnalysis.features?.form, currentAnalysis.features?.social);
        }
      }
    } catch {
      // Ignore if tab query fails
    }
  });
}

/**
 * Tab Activation & Removal Listeners
 */
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const result = tabScanResults.get(activeInfo.tabId);
  if (result) {
    updateBadge(activeInfo.tabId, result.verdict, result.score);
  } else {
    try {
      const tab = await chrome.tabs.get(activeInfo.tabId);
      if (tab && tab.url) {
        performTabScan(tab.id, tab.url);
      }
    } catch {
      // Tab may be closed or restricted
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabScanResults.delete(tabId);
  tabRedirectHistory.delete(tabId);
  tabDownloadContexts.delete(tabId);
  tabDomMetadata.delete(tabId);
  globalEventStore.clearTab(tabId);
});

/**
 * Message Dispatcher for Content Scripts and Extension Popups
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // 1. Content Script Reports DOM Form & Social Engineering Metadata
  if (message.type === 'PHISHGUARD_DOM_METADATA') {
    const tabId = sender.tab?.id;
    const url = sender.url || message.url;
    if (tabId != null && url && sender.frameId === 0 && message.formMetadata) {
      const { formMetadata, socialMeta } = message;
      tabDomMetadata.set(tabId, { url, documentId: sender.documentId, formMetadata, socialMeta });
      const brandEvent = createPageBrandingEvent({
        tabId, url, title: formMetadata.pageTitle, headings: socialMeta?.visibleHeadingsSample
      });
      if (brandEvent) globalEventStore.recordEvent(brandEvent);

      performTabScan(tabId, url, formMetadata, socialMeta).then(result => {
        sendResponse({ success: true, result });
      }).catch(() => sendResponse({ success: false }));
      return true; // async response
    }
  }

  // 2. Popup Requests Current Tab Analysis
  if (message.type === 'GET_CURRENT_ANALYSIS') {
    const tabId = message.tabId;
    const inMemoryResult = tabScanResults.get(tabId);
    if (inMemoryResult) {
      sendResponse({ result: inMemoryResult });
      return false;
    }

    // Check storage session or scan active tab directly
    (async () => {
      const sessionResult = await getSessionData(`tab_${tabId}`);
      if (sessionResult) {
        tabScanResults.set(tabId, sessionResult);
        sendResponse({ result: sessionResult });
        return;
      }

      try {
        const tab = await chrome.tabs.get(tabId);
        if (tab && tab.url) {
          const freshScan = await performTabScan(tab.id, tab.url);
          sendResponse({ result: freshScan });
          return;
        }
      } catch {
        // Tab may have closed
      }

      sendResponse({ result: null });
    })();

    return true; // async response
  }

  // 3. User proceeds through warning interstitial (bypasses warning for domain)
  if (message.type === 'DISMISS_WARNING_FOR_DOMAIN') {
    if (message.domain) {
      const cleanDomain = message.domain.toLowerCase();
      dismissedWarnings.add(cleanDomain);
      (async () => {
        const currentList = await getSessionData('dismissed_domains') || [];
        if (!currentList.includes(cleanDomain)) {
          await setSessionData('dismissed_domains', [...currentList, cleanDomain]);
        }
        sendResponse({ success: true });
      })();
      return true;
    }
    sendResponse({ success: false });
    return false;
  }

  // 4. Force Rescan requested from UI
  if (message.type === 'FORCE_RESCAN') {
    if (message.tabId && message.url) {
      performTabScan(message.tabId, message.url).then(res => {
        sendResponse({ success: true, result: res });
      });
      return true;
    }
  }
});
