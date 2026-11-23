import { UrlFeatures, DetectionSignal } from '../types';
import { SUSPICIOUS_KEYWORDS, HIGH_RISK_TLDS, SUSPICIOUS_PORTS } from '../config/rules';
import { parseDomainHost } from './domainParser';
import { decodePunycodeHostname } from './idn';

/**
 * Parses and extracts deep security features from a URL
 */
export function extractUrlFeatures(rawUrl: string): { features: UrlFeatures; signals: DetectionSignal[] } {
  const signals: DetectionSignal[] = [];
  
  let cleanUrl = rawUrl.trim();
  if (!/^(https?|ftp):\/\//i.test(cleanUrl)) {
    cleanUrl = 'https://' + cleanUrl;
  }

  let parsed: URL;
  try {
    parsed = new URL(cleanUrl);
  } catch {
    try {
      parsed = new URL('https://' + cleanUrl.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ''));
    } catch {
      parsed = new URL('https://invalid-url-format.local');
    }
  }

  const protocol = parsed.protocol.replace(':', '').toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  const path = parsed.pathname;
  const query = parsed.search;
  const port = parsed.port;
  
  // 1. IP Address Detection (IPv4, IPv6, Hex, Integer formats)
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const hexIpPattern = /^0x[0-9a-f]+$/i;
  const intIpPattern = /^\d{8,12}$/;
  
  const isIpv4 = ipv4Pattern.test(hostname);
  // URL.hostname includes square brackets for IPv6 literals.
  const isIpv6 = hostname.startsWith('[') && hostname.endsWith(']');
  const isHexOrInt = hexIpPattern.test(hostname) || intIpPattern.test(hostname);
  const isIpAddress = isIpv4 || isIpv6 || isHexOrInt;

  if (isIpAddress && hostname !== '127.0.0.1' && hostname !== 'localhost' && hostname !== '[::1]') {
    signals.push({
      id: 'SIGNAL_IP_HOST',
      category: 'URL_STRUCTURE',
      type: 'IP_ADDRESS_HOSTNAME',
      severity: 'HIGH',
      weight: 45,
      title: 'IP Address Used as Hostname',
      description: `Website uses a direct IP address (${hostname}) instead of a standard registered domain name. Legitimate web services rarely use raw IP addresses for user-facing web pages.`,
      confidence: 0.95,
      evidence: { hostname }
    });
  }

  // 2. Punycode & IDN Homograph Analysis
  const isPunycode = hostname.split('.').some(part => part.startsWith('xn--'));
  let decodedPunycode: string | undefined;
  
  if (isPunycode) {
    decodedPunycode = decodePunycodeHostname(hostname);
    signals.push({
      id: 'SIGNAL_PUNYCODE_IDN',
      category: 'URL_STRUCTURE',
      type: 'IDN_PUNYCODE_DETECTED',
      severity: 'HIGH',
      weight: 35,
      title: 'Internationalized Domain Name (Punycode / IDN)',
      description: `Domain contains Punycode encoded characters (${hostname}). Attackers frequently use IDN characters to craft visual lookalikes of popular domains.`,
      confidence: 0.90,
      evidence: { hostname, decodedPunycode }
    });
  }

  // URL.hostname is ASCII/Punycode. Inspect the original authority for Unicode.
  const rawAuthority = rawUrl.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split(/[\/?#]/, 1)[0];
  const rawHostPort = rawAuthority.slice(rawAuthority.lastIndexOf('@') + 1);
  const rawHost = rawHostPort.startsWith('[')
    ? rawHostPort.slice(0, rawHostPort.indexOf(']') + 1)
    : rawHostPort.replace(/:\d+$/, '');
  const hasNonAsciiInHost = /[^\u0000-\u007F]/.test(rawHost);
  // A Unicode hostname is normally converted to Punycode by URL. Avoid
  // double-counting the same IDN observation as two independent risk signals.
  if (hasNonAsciiInHost && !isPunycode) {
    signals.push({
      id: 'SIGNAL_NON_ASCII_DOMAIN',
      category: 'URL_STRUCTURE',
      type: 'NON_ASCII_HOST_CHARS',
      severity: 'HIGH',
      weight: 40,
      title: 'Non-ASCII Characters in Hostname',
      description: 'Hostname contains raw Unicode characters outside standard ASCII, which is a common homograph attack technique.',
      confidence: 0.95,
      evidence: { hostname: rawHost }
    });
  }

  // 3. Subdomain Depth and Structure Analysis
  const domainParts = hostname.split('.').filter(Boolean);
  const { registeredDomain: effectiveDomain, subdomainCount } = parseDomainHost(hostname);

  const tld = domainParts.length > 0 ? domainParts[domainParts.length - 1] : '';

  if (subdomainCount >= 3) {
    const depthPenalty = Math.min(20, (subdomainCount - 2) * 8);
    signals.push({
      id: 'SIGNAL_EXCESSIVE_SUBDOMAINS',
      category: 'URL_STRUCTURE',
      type: 'EXCESSIVE_SUBDOMAINS',
      severity: subdomainCount >= 4 ? 'HIGH' : 'MEDIUM',
      weight: 20 + depthPenalty,
      title: `Excessive Subdomain Depth (${subdomainCount} subdomains)`,
      description: `Hostname contains ${subdomainCount} subdomains. Phishing sites frequently stack multiple subdomains (e.g. login.paypal.com.attacker.xyz) to deceive mobile users.`,
      confidence: 0.85,
      evidence: { subdomainCount, effectiveDomain, fullHost: hostname }
    });
  }

  // 4. Deceptive '@' Userinfo Spoofing
  // Accurate RFC 3986 check: only trigger if username/password userinfo component is actually present in URL authority
  const hasUserinfo = Boolean(parsed.username || parsed.password) || rawAuthority.includes('@');

  if (hasUserinfo) {
    signals.push({
      id: 'SIGNAL_USERINFO_SPOOF',
      category: 'URL_STRUCTURE',
      type: 'USERINFO_AUTHENTICATION_SPOOF',
      severity: 'CRITICAL',
      weight: 60,
      title: 'Deceptive User Authentication "@" Spoof',
      description: 'URL contains an "@" symbol in the authority segment. Browsers treat preceding text as user credentials and navigate to the domain after the "@", disguising the actual destination.',
      confidence: 0.98,
      evidence: { rawUrl }
    });
  }

  // 5. Suspicious Port Check
  const hasSuspiciousPort = port !== '' && SUSPICIOUS_PORTS.includes(port);
  if (hasSuspiciousPort) {
    signals.push({
      id: 'SIGNAL_SUSPICIOUS_PORT',
      category: 'URL_STRUCTURE',
      type: 'SUSPICIOUS_NON_STANDARD_PORT',
      severity: 'MEDIUM',
      weight: 22,
      title: `Non-Standard Network Port (:${port})`,
      description: `Website runs on port ${port} instead of standard HTTP (80) or HTTPS (443). Phishing kits frequently host payloads on non-standard ports to evade enterprise filters.`,
      confidence: 0.80,
      evidence: { port }
    });
  }

  // 6. Insecure HTTP Protocol
  if (protocol === 'http' && hostname !== 'localhost' && hostname !== '127.0.0.1' && hostname !== '[::1]') {
    signals.push({
      id: 'SIGNAL_INSECURE_HTTP',
      category: 'URL_STRUCTURE',
      type: 'UNENCRYPTED_HTTP_PROTOCOL',
      severity: 'LOW',
      weight: 15,
      title: 'Unencrypted HTTP Connection',
      description: 'Website does not enforce TLS encryption (HTTPS). Any login credentials or personal data entered can be intercepted in transit.',
      confidence: 0.90,
      evidence: { protocol }
    });
  }

  // 7. High-Risk / Abused TLD Detection
  const hasHighRiskTld = HIGH_RISK_TLDS.includes(tld);
  if (hasHighRiskTld) {
    signals.push({
      id: 'SIGNAL_HIGH_RISK_TLD',
      category: 'URL_STRUCTURE',
      type: 'HIGH_RISK_TOP_LEVEL_DOMAIN',
      severity: 'LOW',
      weight: 12,
      title: `High-Risk Top Level Domain (.${tld})`,
      description: `Domain uses .${tld}, a TLD statistically associated with high volumes of automated spam and disposable phishing campaigns.`,
      confidence: 0.70,
      evidence: { tld }
    });
  }

  // 8. Suspicious Security Keywords in Subdomain, Path or Query
  const searchCorpus = (hostname + path + query).toLowerCase();
  const matchedKeywords: string[] = [];
  
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (searchCorpus.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }

  if (matchedKeywords.length >= 2) {
    const isMainDomainKeyword = matchedKeywords.includes(effectiveDomain.split('.')[0]);
    const weight = isMainDomainKeyword ? 18 : 28;
    
    signals.push({
      id: 'SIGNAL_SUSPICIOUS_KEYWORDS',
      category: 'URL_STRUCTURE',
      type: 'SECURITY_KEYWORDS_DENSITY',
      severity: matchedKeywords.length >= 3 ? 'MEDIUM' : 'LOW',
      weight,
      title: `High Security Keyword Density (${matchedKeywords.length} terms)`,
      description: `URL contains urgent security-themed terms: [${matchedKeywords.slice(0, 4).join(', ')}]. Phishing URLs frequently pack terms like "verify", "secure", and "account" to mimic official portals.`,
      confidence: 0.75,
      evidence: { matchedKeywords }
    });
  }

  // 9. Length & Hyphen Anomalies
  const hyphenCount = (hostname.match(/-/g) || []).length;
  const dotCount = (hostname.match(/\./g) || []).length;
  
  if (rawUrl.length > 120) {
    signals.push({
      id: 'SIGNAL_EXCESSIVE_URL_LENGTH',
      category: 'URL_STRUCTURE',
      type: 'ANOMALOUS_URL_LENGTH',
      severity: 'LOW',
      weight: 10,
      title: `Excessive URL Length (${rawUrl.length} chars)`,
      description: 'The overall URL is unusually long, which is often used in obfuscated phishing links to push the actual host off mobile address bars.',
      confidence: 0.65,
      evidence: { length: rawUrl.length }
    });
  }

  if (hyphenCount >= 3) {
    signals.push({
      id: 'SIGNAL_EXCESSIVE_HYPHENS',
      category: 'URL_STRUCTURE',
      type: 'EXCESSIVE_HYPHENATION',
      severity: 'LOW',
      weight: 14,
      title: `Excessive Domain Hyphenation (${hyphenCount} hyphens)`,
      description: 'Domain uses multiple hyphens to chain brand names with deceptive security words (e.g. paypal-security-update-center).',
      confidence: 0.75,
      evidence: { hyphenCount }
    });
  }

  // 10. Shannon Entropy of Hostname
  const entropy = calculateEntropy(hostname);
  if (entropy > 4.1 && hostname.length > 16 && !isIpAddress) {
    signals.push({
      id: 'SIGNAL_HIGH_ENTROPY_HOST',
      category: 'URL_STRUCTURE',
      type: 'RANDOMIZED_DGA_HOSTNAME',
      severity: 'MEDIUM',
      weight: 24,
      title: 'High Character Entropy (Randomized Hostname)',
      description: 'Hostname has an unusually high degree of randomness, characteristic of Domain Generation Algorithms (DGAs) used by automated botnets and phishing infrastructure.',
      confidence: 0.80,
      evidence: { entropy: entropy.toFixed(2) }
    });
  }

  const features: UrlFeatures = {
    protocol,
    hostname,
    path,
    query,
    port,
    isIpAddress,
    isPunycode,
    decodedPunycode,
    hasNonAsciiInHost,
    subdomainCount,
    domainParts,
    tld,
    hasUserinfo,
    hasSuspiciousPort,
    hasHighRiskTld,
    suspiciousKeywords: matchedKeywords,
    length: rawUrl.length,
    entropy,
    hyphenCount,
    dotCount
  };

  return { features, signals };
}

/**
 * Calculates Shannon Entropy of a string
 */
function calculateEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const frequencies: Record<string, number> = {};
  
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}
