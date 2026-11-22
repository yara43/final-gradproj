import { KNOWN_URL_SHORTENERS } from '../config/brands.js';
function createNavigationSecurityEvent(hop, hopsList = []) {
  let hostname = "";
  let origin = "";
  try {
    const parsed = new URL(hop.url.startsWith("http") ? hop.url : "https://" + hop.url);
    hostname = parsed.hostname.toLowerCase();
    origin = parsed.origin;
  } catch {
    hostname = hop.url.toLowerCase();
    origin = hop.url;
  }
  const hasShortener = hopsList.some((h) => {
    try {
      const u = new URL(h.startsWith("http") ? h : "https://" + h);
      return KNOWN_URL_SHORTENERS.some((s) => u.hostname.endsWith(s));
    } catch {
      return false;
    }
  });
  const hopCount = hopsList.length;
  let severity = "SAFE";
  let title = "Navigation Hop";
  let description = `Navigated to ${hostname}.`;
  if (hopCount >= 3 && hasShortener) {
    severity = "HIGH";
    title = "Multi-Hop Redirect Trampoline via URL Shortener";
    description = `Navigation passed through ${hopCount} redirect hops including intermediary URL shorteners.`;
  } else if (hopCount >= 3) {
    severity = "MEDIUM";
    title = "Multi-Hop Redirect Chain";
    description = `Navigation traversed ${hopCount} redirect hops.`;
  } else if (hasShortener) {
    severity = "LOW";
    title = "URL Shortener Redirection";
    description = `Link resolved through an intermediary URL shortening service.`;
  }
  return {
    id: `nav_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: Date.now(),
    tabId: hop.tabId,
    pageUrl: hop.url,
    pageOrigin: origin,
    type: hopCount > 1 ? "REDIRECT_HOP_OBSERVED" : "NAVIGATION_COMMITTED",
    severity,
    title,
    description,
    initialUrl: hopsList[0] || hop.url,
    redirectHopCount: hopCount,
    hasUrlShortener: hasShortener,
    hopDomains: hopsList.map((h) => {
      try {
        return new URL(h.startsWith("http") ? h : "https://" + h).hostname;
      } catch {
        return h;
      }
    }),
    evidence: {
      hopCount,
      hasShortener,
      hopsList
    }
  };
}
export {
  createNavigationSecurityEvent
};
