import { extractRegisteredDomain } from '../engine/brandIdentity.js';
import { isTrustedFederatedProvider } from '../config/trustedProviders.js';
function createNetworkSecurityEvent(obs, hasActiveCredentialForm = false) {
  let pageHostname = "";
  let destHostname = "";
  let pageOrigin = "";
  try {
    const pageParsed = new URL(obs.pageUrl.startsWith("http") ? obs.pageUrl : "https://" + obs.pageUrl);
    pageHostname = pageParsed.hostname.toLowerCase();
    pageOrigin = pageParsed.origin;
  } catch {
    pageHostname = obs.pageUrl.toLowerCase();
    pageOrigin = obs.pageUrl;
  }
  try {
    const destParsed = new URL(obs.requestUrl.startsWith("http") ? obs.requestUrl : "https://" + obs.requestUrl);
    destHostname = destParsed.hostname.toLowerCase();
  } catch {
    destHostname = obs.requestUrl.toLowerCase();
  }
  const pageRegDomain = extractRegisteredDomain(pageHostname);
  const destRegDomain = extractRegisteredDomain(destHostname);
  const isCrossOrigin = pageRegDomain !== destRegDomain && destHostname !== "" && pageHostname !== "";
  const { isTrusted: isTrustedFederated, provider } = isTrustedFederatedProvider(destHostname);
  const isPost = obs.method.toUpperCase() === "POST";
  const sensitiveSubmissionPattern = isCrossOrigin && isPost && hasActiveCredentialForm && !isTrustedFederated;
  let severity = "SAFE";
  let eventType = "NETWORK_REQUEST_OBSERVED";
  let title = "Network Request Observed";
  let description = `${obs.method} request to ${destHostname}`;
  if (isTrustedFederated) {
    severity = "SAFE";
    eventType = "NETWORK_REQUEST_OBSERVED";
    title = `Legitimate ${provider?.name || "Federated Service"} Request`;
    description = `Authorized communication with trusted provider (${destHostname}).`;
  } else if (sensitiveSubmissionPattern) {
    severity = "CRITICAL";
    eventType = "CREDENTIAL_SUBMISSION_PATTERN";
    title = "Cross-Origin Data Exfiltration Pattern";
    description = `Asynchronous ${obs.method} request dispatched to external domain (${destHostname}) while credentials or sensitive inputs are present.`;
  } else if (isCrossOrigin && isPost) {
    severity = "MEDIUM";
    eventType = "CROSS_ORIGIN_REQUEST_OBSERVED";
    title = "Cross-Origin Form or Data Submission";
    description = `${obs.method} submission directed to external domain (${destHostname}) differing from page origin (${pageHostname}).`;
  } else if (isCrossOrigin) {
    severity = "LOW";
    eventType = "CROSS_ORIGIN_REQUEST_OBSERVED";
    title = "Cross-Origin Communication";
    description = `Sub-resource request to ${destHostname}.`;
  }
  return {
    id: `net_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: obs.timeStamp || Date.now(),
    tabId: obs.tabId,
    frameId: obs.frameId,
    documentId: obs.documentId,
    pageUrl: obs.pageUrl,
    pageOrigin,
    type: eventType,
    severity,
    title,
    description,
    destinationHostname: destHostname,
    isSameOrigin: !isCrossOrigin,
    isCrossOrigin,
    method: obs.method.toUpperCase(),
    destinationUrl: obs.requestUrl,
    requestType: obs.type,
    sensitiveSubmissionPattern,
    evidence: {
      method: obs.method.toUpperCase(),
      destinationHostname: destHostname,
      pageHostname,
      isCrossOrigin,
      requestType: obs.type,
      sensitiveSubmissionPattern,
      isTrustedFederated
    }
  };
}
export {
  createNetworkSecurityEvent
};
