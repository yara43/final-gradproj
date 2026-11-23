/**
 * PhishGuard Core Types & Signal Definitions
 * 
 * Canonical Single Source of Truth for:
 * 1. Chrome Extension Background Worker & Runtime
 * 2. In-browser Security Evaluation Playground / Developer Console
 * 3. Automated Security Test Runner
 */

export type SeverityLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ThreatSeverity = SeverityLevel;

// 5 Risk Tiers for consumer clarity
export type Verdict = 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK' | 'DANGEROUS';

export type SignalCategory = 
  | 'URL_STRUCTURE'
  | 'TYPOSQUATTING'
  | 'DOM_SECURITY'
  | 'REPUTATION'
  | 'REDIRECT_CHAIN'
  | 'REDIRECT'
  | 'SOCIAL_ENGINEERING'
  | 'DOWNLOAD_SECURITY'
  | 'NETWORK_REQUEST'
  | 'PROTOCOL';

export interface DetectionSignal {
  id: string;
  category: SignalCategory;
  type: string;
  severity: ThreatSeverity;
  weight: number; // 0 - 100 base score contribution
  title: string;
  description: string;
  evidence?: Record<string, any>;
  confidence: number; // 0.0 to 1.0
}

export interface ProtectedBrand {
  id: string;
  name: string;
  canonicalDomains: string[];
  keywords: string[];
  category: 'FINANCIAL' | 'TECH' | 'SOCIAL' | 'CRYPTO' | 'ECOMMERCE' | 'PRODUCTIVITY' | 'OTHER';
}

export interface FormAnalysisMetadata {
  hasPasswordInput: boolean;
  hasCreditCardInput: boolean;
  hasSsnInput: boolean;
  hasEmailOrUserInput: boolean;
  has2FAInput: boolean;
  formsCount: number;
  suspiciousForms: Array<{
    action: string;
    method: string;
    isCrossOrigin: boolean;
    isInsecureHttp: boolean;
    identityLabels?: string[];
    hasCreditCardField?: boolean;
    has2FAField?: boolean;
    hasPasswordField: boolean;
    inputCount: number;
    hiddenInputsCount: number;
  }>;
  hasHiddenCredentialFields: boolean;
  hasExternalScriptSources?: string[];
  pageTitle?: string;
}

export interface SocialEngineeringMetadata {
  hasUrgencyLanguage: boolean;
  hasAccountSuspensionNotice: boolean;
  hasCredentialVerificationPrompt: boolean;
  hasFakeTechSupportLanguage: boolean;
  hasPaymentUrgency: boolean;
  hasPrizeOrRewardClaim: boolean;
  detectedPhrases: string[];
  visibleHeadingsSample: string[];
}

export interface UrlFeatures {
  protocol: string;
  hostname: string;
  path: string;
  query: string;
  port: string;
  isIpAddress: boolean;
  isPunycode: boolean;
  decodedPunycode?: string;
  hasNonAsciiInHost: boolean;
  subdomainCount: number;
  domainParts: string[];
  tld: string;
  hasUserinfo: boolean;
  hasSuspiciousPort: boolean;
  hasHighRiskTld: boolean;
  suspiciousKeywords: string[];
  length: number;
  entropy: number;
  hyphenCount: number;
  dotCount: number;
}

export interface RedirectHop {
  url: string;
  timestamp: number;
  statusCode?: number;
}

export interface RedirectAnalysisData {
  initialUrl: string;
  finalUrl: string;
  hops: RedirectHop[];
  hopCount: number;
  hasUrlShortener?: boolean;
  hasShortener?: boolean;
  hasCrossDomainRedirect?: boolean;
  lastUpdated?: number;
}

export type RedirectMetadata = RedirectAnalysisData;

export interface DownloadSecurityContext {
  downloadId: number;
  url: string;
  filename: string;
  fileExtension: string;
  originUrl: string;
  originRiskScore: number;
  originVerdict: Verdict;
  isDangerousOrigin: boolean;
  isExecutable: boolean;
  timestamp: number;
}

export interface SecurityTimelineEvent {
  id: string;
  timestamp: number;
  timeString?: string;
  type: 
    | 'NAVIGATION'
    | 'DOMAIN_EVAL'
    | 'FORM_SECURITY'
    | 'REDIRECT_CHAIN'
    | 'SOCIAL_ENGINEERING'
    | 'DOWNLOAD_CONTEXT'
    | 'RISK_CALC'
    | 'ACTION';
  title: string;
  description: string;
  severity?: ThreatSeverity;
}

export interface SecurityEvidenceItem {
  id: string;
  category: SignalCategory;
  severity: ThreatSeverity;
  weight: number;
  summary: string;
  explanation: string;
}

export interface SecurityAnalysisResult {
  url: string;
  domain: string;
  timestamp: number;
  score: number; // 0 - 100
  severity: ThreatSeverity;
  verdict: Verdict;
  signals: DetectionSignal[];
  evidenceItems: SecurityEvidenceItem[];
  timeline: SecurityTimelineEvent[];
  reasons: string[];
  targetBrand?: ProtectedBrand;
  scanDurationMs: number;
  features?: {
    url?: UrlFeatures;
    form?: FormAnalysisMetadata | null;
    social?: SocialEngineeringMetadata | null;
    redirect?: RedirectAnalysisData | null;
    download?: DownloadSecurityContext | null;
    reputation?: {
      isAllowlisted: boolean;
      isBlocklisted: boolean;
      matchedDomain?: string;
    };
  };
  // Backwards compatibility alias properties
  urlFeatures?: UrlFeatures;
  formFeatures?: FormAnalysisMetadata | null;
  redirectFeatures?: RedirectAnalysisData | null;
  analysisTimeMs?: number;
}

export type AnalysisResult = SecurityAnalysisResult;

export interface ExtensionSettings {
  protectionEnabled: boolean;
  detectionSensitivity: 'CONSERVATIVE' | 'BALANCED' | 'AGGRESSIVE';
  warningThreshold: number; // e.g. 70
  blockThreshold: number; // e.g. 90
  enableUrlAnalysis: boolean;
  enableTyposquatting: boolean;
  enableDomAnalysis: boolean;
  enableSocialEngineering: boolean;
  enableRedirectAnalysis: boolean;
  enableDownloadContext: boolean;
  enableReputationLayer: boolean;
  enableNotifications: boolean;
  protectedBrands: ProtectedBrand[];
  allowlist: string[];
  blocklist: string[];
  developerMode: boolean;
  scanHistoryLimit: number;
}

export interface ScanHistoryItem {
  id: string;
  timestamp: number;
  url: string;
  domain: string;
  score: number;
  severity: ThreatSeverity;
  verdict: Verdict;
  topSignal: string;
  reasons: string[];
  userAction?: 'VISITED' | 'BLOCKED' | 'ALLOWED' | 'DISMISSED';
}

export interface SecurityTestCase {
  id: string;
  name: string;
  description: string;
  category: 
    | 'SAFE_BASELINE' 
    | 'HOMOGLYPH' 
    | 'COMBOSQUAT' 
    | 'RAW_IP' 
    | 'SUBDOMAINS' 
    | 'CREDENTIAL_HARVEST' 
    | 'REDIRECT' 
    | 'SOCIAL_ENGINEERING'
    | 'DOWNLOAD_CONTEXT';
  url: string;
  mockForm?: FormAnalysisMetadata | null;
  mockSocial?: SocialEngineeringMetadata | null;
  mockRedirect?: RedirectAnalysisData | null;
  mockDownload?: DownloadSecurityContext | null;
  expectedVerdict: Verdict;
  expectedMinScore: number;
  expectedMaxScore: number;
  expectedSignals: string[];
}

export interface TestSuiteResult {
  totalTests: number;
  passedTests: number;
  failedTests: number;
  durationMs: number;
  results: Array<{
    testCase: SecurityTestCase;
    passed: boolean;
    actualResult: SecurityAnalysisResult;
    failureReason?: string;
  }>;
}

export type TestRunResult = TestSuiteResult;

// ============================================================================
// THREAT INTELLIGENCE & SECURITY TELEMETRY EVENT LOGGING MODELS
// ============================================================================

export type ThreatIntelStatus = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN' | 'LOOKUP_FAILED';

export interface ThreatIntelProviderResult {
  provider: 'URLHAUS' | 'VIRUSTOTAL' | 'PHISHTANK' | 'SAFE_BROWSING' | 'OPENPHISH';
  status: ThreatIntelStatus;
  isFlagged: boolean;
  scoreContribution: number;
  details: string;
  queryLatencyMs: number;
  lastUpdated?: string;
  metadata?: Record<string, unknown>;
}

export interface ThreatIntelReport {
  overallVerdict: ThreatIntelStatus;
  maxScoreContribution: number;
  providersCount: number;
  flaggedCount: number;
  results: ThreatIntelProviderResult[];
  cached: boolean;
  queriedAt: number;
}

export type SecurityActionTaken =
  | 'SILENT_MONITORING'
  | 'IN_PAGE_BANNER'
  | 'BLOCKING_MODAL'
  | 'FORM_SUBMISSION_INTERCEPTED'
  | 'DOWNLOAD_INTERCEPTED'
  | 'USER_PROCEEDED_OVERRIDE'
  | 'ALLOWLISTED_BYPASS';

export interface InfrastructureSignals {
  isIpAddress: boolean;
  isPunycode: boolean;
  isFreeHosting: boolean;
  freeHostingProvider: string | null;
  hasSuspiciousPort: boolean;
  hasHighRiskTld: boolean;
  subdomainDepth: number;
  entropyScore: number;
  length: number;
  autonomousSystemOrHosting?: string;
}

export interface FormRiskIndicators {
  formsCount: number;
  hasPasswordInput: boolean;
  hasCreditCardInput: boolean;
  hasSsnInput: boolean;
  has2FAInput: boolean;
  hasHiddenCredentialFields: boolean;
  suspiciousFormActions: Array<{
    actionHost: string;
    isCrossOrigin: boolean;
    isInsecureHttp: boolean;
    hasPasswordField: boolean;
    method: string;
  }>;
}

export interface CrossOriginBehavior {
  hasCrossOriginPost: boolean;
  hasCrossOriginCredentialTarget: boolean;
  observedDestinations: string[];
}

export interface RedirectInformation {
  hopCount: number;
  hasShortener: boolean;
  hasCrossDomainRedirect: boolean;
  hops: Array<{
    url: string;
    hostname: string;
    statusCode?: number;
  }>;
}

export interface BrandCandidateInfo {
  name: string;
  confidence: number;
  isImpersonated: boolean;
  canonicalDomains: string[];
  evidence: string[];
}

/**
 * Privacy-Preserving Security Telemetry Log Record
 * Strictly captures metadata, never secrets, passwords, cookies, or payloads.
 */
export interface SecurityTelemetryRecord {
  id: string; // e.g. "tel_1740612345_a8f9"
  analysisId: string;
  timestamp: number;
  timeIso: string;
  url: string; // Sanitized URL (tokens and auth fragments stripped)
  domain: string;
  tld: string;
  pageRiskScore: number; // 0 - 100
  verdict: Verdict;
  severity: ThreatSeverity;
  confidence: number; // 0.0 - 1.0
  extensionVersion: string;
  
  detectedSignals: DetectionSignal[];
  brandCandidates: BrandCandidateInfo[];
  infrastructureSignals: InfrastructureSignals;
  threatIntelligence: ThreatIntelReport;
  formRiskIndicators: FormRiskIndicators;
  crossOriginBehavior: CrossOriginBehavior;
  redirectInformation: RedirectInformation;
  
  actionTaken: SecurityActionTaken;
  wasWarningDisplayed: boolean;
  wasDangerousFormBlocked: boolean;
  wasDownloadBlocked?: boolean;
  
  incidentId?: string; // Associated Security Incident if escalated
  targetBrandName?: string;
  reasons: string[];
}

export type IncidentStatus = 'ACTIVE' | 'INVESTIGATING' | 'MITIGATED' | 'FALSE_POSITIVE' | 'RESOLVED';
export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ThreatCategory = 
  | 'BRAND_IMPERSONATION'
  | 'CREDENTIAL_HARVESTING'
  | 'PAYMENT_FRAUD'
  | '2FA_INTERCEPTION'
  | 'SCAREWARE_TECH_SUPPORT'
  | 'MALWARE_DROPPER'
  | 'TYPOSQUAT_CAMPAIGN'
  | 'REDIRECT_SMUGGLING';

export interface MitreTechnique {
  id: string; // e.g. "T1566.002"
  name: string; // e.g. "Spearphishing Link"
  tactic: string; // e.g. "Initial Access"
  url?: string;
}

export interface AnalystNote {
  id: string;
  author: string;
  timestamp: number;
  text: string;
}

export interface IndicatorOfCompromise {
  type: 'DOMAIN' | 'URL' | 'IP' | 'SHA256' | 'BRAND_TERM';
  value: string;
  description: string;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
}

/**
 * Security Incident Model for Security Operations & Triage
 */
export interface SecurityIncident {
  incidentId: string; // e.g. "INC-2026-0841"
  title: string;
  threatCategory: ThreatCategory;
  severity: IncidentSeverity;
  status: IncidentStatus;
  riskScore: number;
  affectedDomain: string;
  targetBrand?: string;
  
  createdAt: number;
  updatedAt: number;
  
  mitreTechniques: MitreTechnique[];
  iocs: IndicatorOfCompromise[];
  
  telemetryLogIds: string[];
  firstSeenLog?: SecurityTelemetryRecord;
  
  analystNotes: AnalystNote[];
  recommendedMitigations: string[];
  
  assignedAnalyst?: string;
  resolvedAt?: number;
}
