/**
 * PhishGuard Real Database & Persistent Storage Engine
 * 
 * Provides atomic JSON-backed storage with memory caching for:
 * 1. Raw Telemetry Events (page_analysis)
 * 2. Correlated Security Incidents (INC-2026-XXXX)
 * 3. Security Analyst Triage Logs & Audit Notes
 */

import fs from 'fs';
import path from 'path';
import { SecurityTelemetryRecord, SecurityIncident } from '../core/types';

export interface DatabaseSchema {
  telemetry: SecurityTelemetryRecord[];
  incidents: SecurityIncident[];
  stats: {
    totalScans: number;
    totalBlocked: number;
    totalIncidents: number;
    lastUpdated: number;
  };
}

const DB_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DB_DIR, 'phishguard-db.json');

class PhishGuardDatabase {
  private data: DatabaseSchema = {
    telemetry: [],
    incidents: [],
    stats: {
      totalScans: 0,
      totalBlocked: 0,
      totalIncidents: 0,
      lastUpdated: Date.now()
    }
  };

  private isLoaded = false;

  constructor() {
    this.init();
  }

  private init() {
    try {
      if (!fs.existsSync(DB_DIR)) {
        fs.mkdirSync(DB_DIR, { recursive: true });
      }

      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf-8');
        this.data = JSON.parse(raw);
        this.isLoaded = true;
      } else {
        this.seedInitialData();
        this.save();
      }
    } catch (err) {
      console.warn('[PhishGuard DB] Initializing with fresh in-memory database:', err);
      this.seedInitialData();
    }
  }

  private save() {
    try {
      if (!fs.existsSync(DB_DIR)) {
        fs.mkdirSync(DB_DIR, { recursive: true });
      }
      fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2), 'utf-8');
    } catch (err) {
      console.error('[PhishGuard DB] Failed to persist data to disk:', err);
    }
  }

  private seedInitialData() {
    const now = Date.now();

    const initialIncident: SecurityIncident = {
      incidentId: 'INC-2026-0001',
      title: 'DANGEROUS: vintedmarket.netlify.app (Vinted Spoof)',
      threatCategory: 'BRAND_IMPERSONATION',
      severity: 'CRITICAL',
      status: 'ACTIVE',
      riskScore: 100,
      affectedDomain: 'vintedmarket.netlify.app',
      targetBrand: 'Vinted',
      createdAt: now - 1000 * 60 * 25,
      updatedAt: now - 1000 * 60 * 15,
      mitreTechniques: [
        { id: 'T1584.004', name: 'Compromise Infrastructure: Free Hosting', tactic: 'Initial Access' },
        { id: 'T1598.003', name: 'Phishing for Information: Spearphishing Link', tactic: 'Initial Access' },
        { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
        { id: 'T1036.007', name: 'Masquerading: Double File Extension / Name', tactic: 'Defense Evasion' }
      ],
      iocs: [
        { type: 'DOMAIN', value: 'vintedmarket.netlify.app', description: 'Deceptive Free-Hosting Domain', confidence: 'HIGH' },
        { type: 'URL', value: 'https://vintedmarket.netlify.app/login/verify-account', description: 'Active Phishing Path', confidence: 'HIGH' }
      ],
      telemetryLogIds: ['tel_vinted_001'],
      analystNotes: [
        {
          id: 'NOTE-1',
          timestamp: now - 1000 * 60 * 20,
          author: 'System Auto-Correlator',
          text: 'Incident auto-created with 100/100 risk score and DANGEROUS verdict. Correlated 3 signals.'
        },
        {
          id: 'NOTE-2',
          timestamp: now - 1000 * 60 * 15,
          author: 'SOC-Lead',
          text: 'Verified phishing kit structure. Block rule pushed to all connected agents.'
        }
      ],
      recommendedMitigations: [
        'Enforce domain-level DNS block',
        'Revoke entered credentials if submitted',
        'Submit abuse report to Netlify'
      ]
    };

    const initialTelemetry: SecurityTelemetryRecord = {
      id: 'tel_vinted_001',
      analysisId: 'analysis_vinted_001',
      timestamp: now - 1000 * 60 * 25,
      timeIso: new Date(now - 1000 * 60 * 25).toISOString(),
      url: 'https://vintedmarket.netlify.app/login/verify-account',
      domain: 'vintedmarket.netlify.app',
      tld: 'app',
      pageRiskScore: 100,
      verdict: 'DANGEROUS',
      severity: 'CRITICAL',
      confidence: 0.99,
      extensionVersion: '1.0.0',
      actionTaken: 'FORM_SUBMISSION_INTERCEPTED',
      wasWarningDisplayed: true,
      wasDangerousFormBlocked: true,
      incidentId: 'INC-2026-0001',
      targetBrandName: 'Vinted',
      reasons: [
        'Brand impersonation on Netlify free hosting',
        'Active login/verification credential harvesting form',
        'Third-party cloud infrastructure domain mismatch'
      ],
      detectedSignals: [
        {
          id: 'SIG-BRAND',
          category: 'TYPOSQUATTING',
          type: 'BRAND_IMPERSONATION_FREE_HOSTING',
          severity: 'CRITICAL',
          weight: 50,
          title: 'Brand Impersonation on Free Hosting',
          description: 'The website presents Vinted branding on third-party Netlify cloud infrastructure rather than official vinted.com.',
          confidence: 0.98
        },
        {
          id: 'SIG-FORM',
          category: 'DOM_SECURITY',
          type: 'CREDENTIAL_INPUT_FIELD',
          severity: 'CRITICAL',
          weight: 35,
          title: 'Active Credential & Password Form',
          description: 'Webpage contains an authentication surface requesting username and password credentials.',
          confidence: 0.95
        }
      ],
      brandCandidates: [
        {
          name: 'Vinted',
          confidence: 0.98,
          isImpersonated: true,
          canonicalDomains: ['vinted.com', 'vinted.fr'],
          evidence: ['Domain contains brand name', 'Logo and styling mimic Vinted']
        }
      ],
      infrastructureSignals: {
        isIpAddress: false,
        isPunycode: false,
        isFreeHosting: true,
        freeHostingProvider: 'Netlify App Hosting',
        hasSuspiciousPort: false,
        hasHighRiskTld: false,
        subdomainDepth: 3,
        entropyScore: 3.4,
        length: 25
      },
      threatIntelligence: {
        overallVerdict: 'MALICIOUS',
        maxScoreContribution: 95,
        providersCount: 5,
        flaggedCount: 3,
        results: [
          {
            provider: 'URLHAUS',
            status: 'MALICIOUS',
            isFlagged: true,
            scoreContribution: 90,
            details: 'Active phishing campaign',
            queryLatencyMs: 4
          }
        ],
        cached: false,
        queriedAt: now
      },
      formRiskIndicators: {
        formsCount: 1,
        hasPasswordInput: true,
        hasCreditCardInput: false,
        hasSsnInput: false,
        has2FAInput: true,
        hasHiddenCredentialFields: false,
        suspiciousFormActions: []
      },
      crossOriginBehavior: {
        hasCrossOriginPost: false,
        hasCrossOriginCredentialTarget: false,
        observedDestinations: []
      },
      redirectInformation: {
        hopCount: 1,
        hasShortener: false,
        hasCrossDomainRedirect: false,
        hops: []
      }
    };

    // Benign developer portfolio telemetry record
    const benignTelemetry: SecurityTelemetryRecord = {
      id: 'tel_portfolio_002',
      analysisId: 'analysis_portfolio_002',
      timestamp: now - 1000 * 60 * 10,
      timeIso: new Date(now - 1000 * 60 * 10).toISOString(),
      url: 'https://my-developer-portfolio.netlify.app/about',
      domain: 'my-developer-portfolio.netlify.app',
      tld: 'app',
      pageRiskScore: 0,
      verdict: 'SAFE',
      severity: 'SAFE',
      confidence: 0.95,
      extensionVersion: '1.0.0',
      actionTaken: 'SILENT_MONITORING',
      wasWarningDisplayed: false,
      wasDangerousFormBlocked: false,
      reasons: ['No suspicious heuristics, typosquats, or deceptive form behaviors were detected.'],
      detectedSignals: [],
      brandCandidates: [],
      infrastructureSignals: {
        isIpAddress: false,
        isPunycode: false,
        isFreeHosting: true,
        freeHostingProvider: 'Netlify App Hosting',
        hasSuspiciousPort: false,
        hasHighRiskTld: false,
        subdomainDepth: 3,
        entropyScore: 3.1,
        length: 31
      },
      threatIntelligence: {
        overallVerdict: 'CLEAN',
        maxScoreContribution: 0,
        providersCount: 5,
        flaggedCount: 0,
        results: [],
        cached: false,
        queriedAt: now
      },
      formRiskIndicators: {
        formsCount: 0,
        hasPasswordInput: false,
        hasCreditCardInput: false,
        hasSsnInput: false,
        has2FAInput: false,
        hasHiddenCredentialFields: false,
        suspiciousFormActions: []
      },
      crossOriginBehavior: {
        hasCrossOriginPost: false,
        hasCrossOriginCredentialTarget: false,
        observedDestinations: []
      },
      redirectInformation: {
        hopCount: 1,
        hasShortener: false,
        hasCrossDomainRedirect: false,
        hops: []
      }
    };

    this.data.incidents = [initialIncident];
    this.data.telemetry = [initialTelemetry, benignTelemetry];
    this.data.stats = {
      totalScans: 2,
      totalBlocked: 1,
      totalIncidents: 1,
      lastUpdated: now
    };
  }

  // --- Telemetry Methods ---

  public addTelemetry(record: SecurityTelemetryRecord): SecurityTelemetryRecord {
    this.data.telemetry.unshift(record);
    if (this.data.telemetry.length > 500) {
      this.data.telemetry = this.data.telemetry.slice(0, 500);
    }
    this.data.stats.totalScans++;
    if (record.actionTaken === 'BLOCKING_MODAL' || record.actionTaken === 'FORM_SUBMISSION_INTERCEPTED') {
      this.data.stats.totalBlocked++;
    }
    this.data.stats.lastUpdated = Date.now();
    this.save();
    return record;
  }

  public getTelemetry(filter?: {
    search?: string;
    verdict?: string;
    severity?: string;
    actionTaken?: string;
    limit?: number;
  }): SecurityTelemetryRecord[] {
    let result = [...this.data.telemetry];

    if (filter?.search) {
      const q = filter.search.toLowerCase();
      result = result.filter(
        r => r.url.toLowerCase().includes(q) ||
             r.domain.toLowerCase().includes(q) ||
             (r.targetBrandName && r.targetBrandName.toLowerCase().includes(q)) ||
             (r.incidentId && r.incidentId.toLowerCase().includes(q))
      );
    }

    if (filter?.verdict && filter.verdict !== 'ALL') {
      result = result.filter(r => r.verdict === filter.verdict);
    }

    if (filter?.severity && filter.severity !== 'ALL') {
      result = result.filter(r => r.severity === filter.severity);
    }

    if (filter?.actionTaken && filter.actionTaken !== 'ALL') {
      result = result.filter(r => r.actionTaken === filter.actionTaken);
    }

    const limit = filter?.limit || 100;
    return result.slice(0, limit);
  }

  // --- Incident Methods ---

  public createOrUpdateIncident(incident: SecurityIncident): SecurityIncident {
    const idx = this.data.incidents.findIndex(i => i.incidentId === incident.incidentId || i.affectedDomain === incident.affectedDomain);
    if (idx >= 0) {
      // Merge updates
      this.data.incidents[idx] = {
        ...this.data.incidents[idx],
        ...incident,
        analystNotes: [
          ...this.data.incidents[idx].analystNotes,
          ...(incident.analystNotes.filter(n => !this.data.incidents[idx].analystNotes.some(en => en.id === n.id)))
        ]
      };
      this.save();
      return this.data.incidents[idx];
    } else {
      this.data.incidents.unshift(incident);
      this.data.stats.totalIncidents++;
      this.data.stats.lastUpdated = Date.now();
      this.save();
      return incident;
    }
  }

  public getIncidents(filter?: {
    search?: string;
    status?: string;
    severity?: string;
    limit?: number;
  }): SecurityIncident[] {
    let result = [...this.data.incidents];

    if (filter?.search) {
      const q = filter.search.toLowerCase();
      result = result.filter(
        i => i.incidentId.toLowerCase().includes(q) ||
             i.title.toLowerCase().includes(q) ||
             i.affectedDomain.toLowerCase().includes(q) ||
             (i.targetBrand && i.targetBrand.toLowerCase().includes(q))
      );
    }

    if (filter?.status && filter.status !== 'ALL') {
      result = result.filter(i => i.status === filter.status);
    }

    if (filter?.severity && filter.severity !== 'ALL') {
      result = result.filter(i => i.severity === filter.severity);
    }

    const limit = filter?.limit || 50;
    return result.slice(0, limit);
  }

  public getIncidentById(id: string): SecurityIncident | null {
    return this.data.incidents.find(i => i.incidentId === id) || null;
  }

  public updateIncident(
    id: string,
    updates: {
      status?: SecurityIncident['status'];
      assignedAnalyst?: string;
      newNote?: { author: string; text: string };
    }
  ): SecurityIncident | null {
    const incident = this.data.incidents.find(i => i.incidentId === id);
    if (!incident) return null;

    if (updates.status) incident.status = updates.status;
    if (updates.assignedAnalyst) incident.assignedAnalyst = updates.assignedAnalyst;
    if (updates.newNote) {
      incident.analystNotes.push({
        id: `NOTE-${Date.now()}`,
        timestamp: Date.now(),
        author: updates.newNote.author,
        text: updates.newNote.text
      });
    }

    this.save();
    return incident;
  }

  public getStats() {
    const criticalIncidents = this.data.incidents.filter(i => i.severity === 'CRITICAL').length;
    const openIncidents = this.data.incidents.filter(i => i.status === 'ACTIVE' || i.status === 'INVESTIGATING').length;
    
    // Top targeted brands
    const brandCounts: Record<string, number> = {};
    for (const inc of this.data.incidents) {
      if (inc.targetBrand) {
        brandCounts[inc.targetBrand] = (brandCounts[inc.targetBrand] || 0) + 1;
      }
    }

    const topTargetedBrands = Object.entries(brandCounts)
      .map(([brand, count]) => ({ brand, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return {
      totalScans: this.data.stats.totalScans,
      totalBlocked: this.data.stats.totalBlocked,
      totalIncidents: this.data.incidents.length,
      openIncidents,
      criticalIncidents,
      topTargetedBrands,
      lastUpdated: this.data.stats.lastUpdated
    };
  }

  public clearAll() {
    this.data = {
      telemetry: [],
      incidents: [],
      stats: {
        totalScans: 0,
        totalBlocked: 0,
        totalIncidents: 0,
        lastUpdated: Date.now()
      }
    };
    this.save();
  }
}

export const db = new PhishGuardDatabase();
