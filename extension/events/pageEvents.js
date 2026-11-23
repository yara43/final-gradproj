import { inferBrandIdentity, evaluateBrandDomainMismatch, extractRegisteredDomain } from '../engine/brandIdentity.js';
function createPageBrandingEvent(input) {
  let hostname = "";
  let origin = "";
  try {
    const parsed = new URL(input.url.startsWith("http") ? input.url : "https://" + input.url);
    hostname = parsed.hostname.toLowerCase();
    origin = parsed.origin;
  } catch {
    hostname = input.url.toLowerCase();
    origin = input.url;
  }
  const registeredDomain = extractRegisteredDomain(hostname);
  const visibleTokens = [...input.headings || [], ...input.metaTokens || []];
  const candidate = inferBrandIdentity(hostname, input.title, visibleTokens, input.formMetadata);
  if (!candidate) {
    return null;
  }
  const mismatchEval = evaluateBrandDomainMismatch(hostname, candidate);
  if (!mismatchEval) {
    return null;
  }
  const isFreeHosting = mismatchEval.isFreeHostingAbuse;
  const isOfficial = mismatchEval.isOfficial;
  let severity = "SAFE";
  let eventType = "BRAND_IDENTITY_DETECTED";
  let title = `Verified ${candidate.candidateName} Domain`;
  let description = `Official authentic service for ${candidate.candidateName}.`;
  if (!isOfficial) {
    if (isFreeHosting) {
      severity = "CRITICAL";
      eventType = "FREE_HOSTING_DETECTED";
      title = `${candidate.candidateName} Impersonation on Free Hosting`;
      description = `Website displays ${candidate.candidateName} branding on third-party cloud platform (${mismatchEval.freeHostingProvider}) rather than official ${candidate.canonicalDomains[0]}.`;
    } else {
      severity = "HIGH";
      eventType = "DOMAIN_MISMATCH_DETECTED";
      title = `Brand Domain Mismatch (${candidate.candidateName})`;
      description = `Website claims to represent ${candidate.candidateName}, but hostname (${hostname}) does not match official domain (${candidate.canonicalDomains[0]}).`;
    }
  }
  return {
    id: `brand_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: Date.now(),
    tabId: input.tabId,
    pageUrl: input.url,
    pageOrigin: origin,
    type: eventType,
    severity,
    title,
    description,
    claimedBrandName: candidate.candidateName,
    canonicalDomains: candidate.canonicalDomains,
    currentHostname: hostname,
    currentRegisteredDomain: registeredDomain,
    isFreeHostingProvider: isFreeHosting,
    freeHostingProviderName: mismatchEval.freeHostingProvider,
    isOfficialDomain: isOfficial,
    brandTokensFound: candidate.evidence,
    pageTitle: input.title,
    evidence: {
      candidateName: candidate.candidateName,
      canonicalDomains: candidate.canonicalDomains,
      hostname,
      registeredDomain,
      isOfficial,
      isFreeHosting,
      freeHostingProvider: mismatchEval.freeHostingProvider,
      confidence: candidate.confidence,
      evidenceList: candidate.evidence
    }
  };
}
export {
  createPageBrandingEvent
};
