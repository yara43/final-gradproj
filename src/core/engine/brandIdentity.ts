/**
 * PhishGuard Generalized Brand Identity & Domain Hierarchy Engine
 * 
 * Accurately models and distinguishes:
 * 1. BRAND IDENTITY: The real-world entity (e.g., "Vinted", "Jumia", "PayPal", "Apple", "Acme Bank")
 *    - Layer A: Known Protected Brand Engine (High-confidence curated registry)
 *    - Layer B: Generalized / Inferred Identity Engine (Arbitrary brands inferred from DOM, meta, title, headings, and tokens)
 * 2. REGISTERED DOMAIN (eTLD+1, including private suffixes): The registrable site
 *    (e.g., "vinted.com", "alice.netlify.app", "bob.vercel.app", "jumia.com")
 * 3. HOSTNAME: The full network name (e.g., "vintedmarket.netlify.app", "jumia.vercel.app", "accounts.google.com")
 * 
 * Identifies brand domain mismatches and impersonations across:
 * - Free cloud hosting / bucket subdomains (Netlify, Vercel, Firebase, Render, Pages.dev, etc.)
 * - Combosquatting & Typosquatting
 * - Deceptive page titles & branding on unrelated registered domains
 */

import { FormAnalysisMetadata, SocialEngineeringMetadata } from '../types';
import { parseDomainHost } from './domainParser';

export interface BrandIdentity {
  id: string;
  name: string;
  canonicalDomains: string[];
  regionalDomains?: string[];
  knownAuthDomains?: string[];
  knownPaymentDomains?: string[];
  aliases: string[];
  keywords: string[];
  category: 'ECOMMERCE' | 'FINANCIAL' | 'TECH' | 'SOCIAL' | 'CRYPTO' | 'LOGISTICS' | 'PRODUCTIVITY' | 'OTHER';
}

export interface BrandIdentityCandidate {
  domainOwnerId?: string;
  mentionedBrandIds?: string[];
  candidateName: string;
  confidence: number; // 0.0 to 1.0
  evidence: string[];
  source: 'KNOWN_REGISTRY' | 'STRUCTURED_DATA' | 'META_TAGS' | 'DOCUMENT_TITLE' | 'HEADINGS' | 'HOSTNAME_TOKEN' | 'LOGIN_TEXT';
  isKnownBrand: boolean;
  knownBrandId?: string;
  canonicalDomains: string[];
}

export const KNOWN_BRANDS: BrandIdentity[] = [
  { id: 'twitter', name: 'X / Twitter', canonicalDomains: ['x.com', 'twitter.com'], keywords: ['twitter'], category: 'SOCIAL', aliases: ['twitter', 'x'] },
  {
    id: 'vinted',
    name: 'Vinted',
    canonicalDomains: [
      'vinted.com', 'vinted.fr', 'vinted.de', 'vinted.co.uk',
      'vinted.es', 'vinted.it', 'vinted.pl', 'vinted.lt', 'vinted.cz',
      'vinted.nl', 'vinted.be', 'vinted.at', 'vinted.se'
    ],
    aliases: ['vinted', 'vinted uk', 'vinted marketplace', 'vinted fr', 'vinted de'],
    keywords: ['vinted', 'vintedmarket', 'second hand', 'wardrobe', 'vinted balance'],
    category: 'ECOMMERCE'
  },
  {
    id: 'jumia',
    name: 'Jumia',
    canonicalDomains: [
      'jumia.com', 'jumia.com.ng', 'jumia.co.ke', 'jumia.ma', 'jumia.ci', 'jumia.ug', 'jumia.com.gh', 'jumia.com.eg'
    ],
    aliases: ['jumia', 'jumia store', 'jumia online', 'jumia market'],
    keywords: ['jumia', 'jumia store', 'jumia market', 'jumia pay'],
    category: 'ECOMMERCE'
  },
  {
    id: 'paypal',
    name: 'PayPal',
    canonicalDomains: ['paypal.com', 'paypal-objects.com', 'paypal.me', 'paypal-community.com'],
    knownAuthDomains: ['www.paypal.com/signin', 'paypal.com/auth'],
    knownPaymentDomains: ['checkout.paypal.com', 'paypal.com/checkout'],
    aliases: ['paypal', 'paypal inc', 'paypal security'],
    keywords: ['paypal', 'paypaii', 'paypai', 'paypal balance', 'send money'],
    category: 'FINANCIAL'
  },
  {
    id: 'google',
    name: 'Google / Gmail',
    canonicalDomains: ['google.com', 'google.co.uk', 'google.ca', 'gmail.com', 'accounts.google.com', 'gstatic.com', 'googleusercontent.com'],
    knownAuthDomains: ['accounts.google.com'],
    aliases: ['google', 'gmail', 'google workspace', 'google account'],
    keywords: ['google', 'gmail', 'g00gle', 'goog1e', 'google sign in'],
    category: 'TECH'
  },
  {
    id: 'microsoft',
    name: 'Microsoft / Outlook / Office',
    canonicalDomains: ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'outlook.com', 'microsoftonline.com', 'msn.com', 'sharepoint.com'],
    knownAuthDomains: ['login.microsoftonline.com', 'login.live.com'],
    aliases: ['microsoft', 'outlook', 'office 365', 'microsoft 365'],
    keywords: ['microsoft', 'outlook', 'office365', 'micros0ft', 'ms-online'],
    category: 'TECH'
  },
  {
    id: 'apple',
    name: 'Apple / iCloud',
    canonicalDomains: ['apple.com', 'icloud.com', 'appleid.apple.com', 'itunes.com'],
    knownAuthDomains: ['appleid.apple.com'],
    aliases: ['apple', 'icloud', 'apple id'],
    keywords: ['apple', 'icloud', 'appl-id', 'apple-id', 'apple id sign in'],
    category: 'TECH'
  },
  {
    id: 'amazon',
    name: 'Amazon',
    canonicalDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com', 'media-amazon.com'],
    aliases: ['amazon', 'aws', 'amazon prime'],
    keywords: ['amazon', 'amaz0n', 'amazon prime', 'amazon order'],
    category: 'ECOMMERCE'
  },
  {
    id: 'netflix',
    name: 'Netflix',
    canonicalDomains: ['netflix.com', 'nflxvideo.net', 'netflix.net'],
    aliases: ['netflix', 'netflix streaming'],
    keywords: ['netflix', 'netf1ix', 'netflix account', 'netflix billing'],
    category: 'TECH'
  },
  {
    id: 'chase',
    name: 'Chase Bank',
    canonicalDomains: ['chase.com', 'jpmorganchase.com'],
    aliases: ['chase', 'jpmorgan chase', 'chase online'],
    keywords: ['chase', 'chase bank', 'chase online', 'jpmorgan'],
    category: 'FINANCIAL'
  },
  {
    id: 'wellsfargo',
    name: 'Wells Fargo',
    canonicalDomains: ['wellsfargo.com'],
    aliases: ['wells fargo', 'wf bank'],
    keywords: ['wellsfargo', 'wells fargo', 'wf online'],
    category: 'FINANCIAL'
  },
  {
    id: 'bankofamerica',
    name: 'Bank of America',
    canonicalDomains: ['bankofamerica.com', 'bofa.com'],
    aliases: ['bank of america', 'bofa'],
    keywords: ['bankofamerica', 'bofa', 'bofa online banking'],
    category: 'FINANCIAL'
  },
  {
    id: 'meta',
    name: 'Meta / Facebook / Instagram',
    canonicalDomains: ['facebook.com', 'fb.com', 'instagram.com', 'meta.com', 'messenger.com', 'whatsapp.com'],
    aliases: ['facebook', 'instagram', 'meta', 'whatsapp'],
    keywords: ['facebook', 'instagram', 'meta', 'fb login'],
    category: 'SOCIAL'
  },
  {
    id: 'binance',
    name: 'Binance',
    canonicalDomains: ['binance.com', 'binance.us', 'bnbstatic.com'],
    aliases: ['binance', 'binance exchange'],
    keywords: ['binance', 'binance wallet', 'bnb'],
    category: 'CRYPTO'
  },
  {
    id: 'coinbase',
    name: 'Coinbase',
    canonicalDomains: ['coinbase.com', 'pro.coinbase.com'],
    aliases: ['coinbase', 'coinbase exchange'],
    keywords: ['coinbase', 'c0inbase', 'coinbase wallet'],
    category: 'CRYPTO'
  },
  {
    id: 'github',
    name: 'GitHub',
    canonicalDomains: ['github.com', 'githubusercontent.com', 'github.blog'],
    aliases: ['github', 'github inc'],
    keywords: ['github', 'g1thub', 'github sign in'],
    category: 'TECH'
  },
  {
    id: 'stripe',
    name: 'Stripe',
    canonicalDomains: ['stripe.com', 'checkout.stripe.com', 'stripe.network'],
    aliases: ['stripe', 'stripe payments'],
    keywords: ['stripe', 'stripe checkout', 'powered by stripe'],
    category: 'FINANCIAL'
  },
  {
    id: 'steam',
    name: 'Steam / Valve',
    canonicalDomains: ['steampowered.com', 'steamcommunity.com', 'valvesoftware.com'],
    aliases: ['steam', 'valve', 'steam community'],
    keywords: ['steam', 'steam community', 'steam login', 'steam guard'],
    category: 'TECH'
  },
  {
    id: 'docusign',
    name: 'DocuSign',
    canonicalDomains: ['docusign.com', 'docusign.net'],
    aliases: ['docusign', 'docusign inc'],
    keywords: ['docusign', 'sign document', 'docusign envelope'],
    category: 'PRODUCTIVITY'
  },
  {
    id: 'dhl',
    name: 'DHL Express',
    canonicalDomains: ['dhl.com', 'dhl.de', 'dhl.co.uk', 'dhl-express.com'],
    aliases: ['dhl', 'dhl express'],
    keywords: ['dhl', 'dhl tracking', 'dhl delivery', 'shipment delivery'],
    category: 'LOGISTICS'
  }
];

/**
 * Known Free Hosting / Multi-Tenant Cloud Web App Providers
 */
export const FREE_HOSTING_PROVIDERS: Record<string, string> = {
  'netlify.app': 'Netlify App Hosting',
  'vercel.app': 'Vercel Platform',
  'firebaseapp.com': 'Google Firebase',
  'web.app': 'Google Firebase Web',
  'pages.dev': 'Cloudflare Pages',
  'workers.dev': 'Cloudflare Workers',
  'github.io': 'GitHub Pages',
  'gitlab.io': 'GitLab Pages',
  'glitch.me': 'Glitch Hosting',
  'render.com': 'Render Cloud',
  'onrender.com': 'Render Cloud App',
  'surge.sh': 'Surge Static Web',
  'herokuapp.com': 'Heroku Cloud',
  'supabase.co': 'Supabase Storage/Auth',
  's3.amazonaws.com': 'AWS S3 Bucket',
  'blob.core.windows.net': 'Azure Blob Storage',
  '000webhostapp.com': '000Webhost Free Tier',
  'weebly.com': 'Weebly Free Site',
  'wixsite.com': 'Wix Free Subdomain',
  'sites.google.com': 'Google Sites Free',
  'godaddysites.com': 'GoDaddy Free Site Builder'
};

/**
 * Registered domain extraction using the Public Suffix List, including private suffixes.
 */
export function sharedHost(hostname: string) {
  return Object.keys(FREE_HOSTING_PROVIDERS).find(provider =>
    hostname === provider || hostname.endsWith('.' + provider)
  );
}

export function extractRegisteredDomain(hostname: string): string {
  return parseDomainHost(hostname).registeredDomain;
}

export interface BrandEvaluationResult {
  candidate: BrandIdentityCandidate;
  isOfficial: boolean;
  isSubdomainAbuse: boolean;
  isFreeHostingAbuse: boolean;
  isCombosquat: boolean;
  freeHostingProvider?: string;
  details: string;
}

/**
 * UNKNOWN BRAND / GENERIC IDENTITY ENGINE:
 * Safely infers claimed identity from safe structural DOM metadata, page title, and hostname tokens.
 */
export function inferBrandIdentity(
  hostname: string,
  pageTitle?: string,
  visibleTokens: string[] = [],
  formMeta?: FormAnalysisMetadata | null,
  socialMeta?: SocialEngineeringMetadata | null,
  customBrands: BrandIdentity[] = KNOWN_BRANDS
): BrandIdentityCandidate | null {
  const host = hostname.trim().toLowerCase().replace(/\.$/, '');
  const provider = sharedHost(host);
  const tenant = provider ? host.slice(0, -(provider.length + 1)) : host;
  const norm = (s: string) => s.trim().toLowerCase().replace(/\s+/g, ' ');
  const title = norm(pageTitle || '');
  const headings = visibleTokens.map(norm);
  const labels = (formMeta?.suspiciousForms || []).filter(f => f.hasPasswordField || f.has2FAField).flatMap(f => f.identityLabels || []).map(norm);
  const rows = customBrands.map(brand => {
    const names = [brand.id, ...brand.aliases, brand.name].map(norm);
    const login = (t: string, n: string) => ['sign in to ', 'log in to ', 'login to ', 'تسجيل الدخول إلى '].some(p => t === p+n) || [' login', ' sign in', ' account login'].some(p => t === n+p);
    const formClaim = labels.some(t => names.some(n => login(t,n) || (n.length > 1 && t === n)));
    const titleClaim = names.some(n => login(title,n) || (n.length > 1 && title === n));
    const hostMatch = [brand.id,...brand.keywords].some(k => k.length >= 3 && tenant.includes(k.toLowerCase().replace(/\s+/g,'')));
    const official = !provider && brand.canonicalDomains.some(d => host === d || host.endsWith('.'+d));
    const mentioned = [title,...headings].some(t => names.some(n => t === n || (n.length > 1 && t.split(/[^\p{L}\p{N}]+/u).includes(n))));
    return {brand, formClaim, titleClaim, hostMatch, official, mentioned};
  }).sort((a,b) => a.brand.id.localeCompare(b.brand.id));
  const owner = rows.find(r => r.official);
  const row = rows.find(r => r.formClaim && r !== owner) || owner || rows.find(r => r.formClaim) || rows.find(r => r.titleClaim) || rows.find(r => r.hostMatch);
  if (!row) return null; // Unknown identity: no verified domain to compare against.
  return { candidateName: row.brand.name, confidence: row.official ? 0.99 : 0.85,
    source: 'KNOWN_REGISTRY', isKnownBrand: true, knownBrandId: row.brand.id,
    domainOwnerId: owner?.brand.id, mentionedBrandIds: rows.filter(r => r.mentioned).map(r => r.brand.id),
    canonicalDomains: row.brand.canonicalDomains,
    evidence: [row.official ? 'Official domain' : row.formClaim ? 'Brand claim inside credential form' : row.titleClaim ? 'Page title claims this identity' : 'Brand token in hostname'] };
}

/**
 * Evaluates Brand / Domain Mismatch generically across both known and inferred brand candidates
 */
export function evaluateBrandDomainMismatch(
  hostname: string,
  candidate: BrandIdentityCandidate | null
): BrandEvaluationResult | null {
  if (!candidate) return null;

  const cleanHostname = hostname.toLowerCase().trim();
  const registeredDomain = extractRegisteredDomain(cleanHostname);

  // Check if current hostname is on a known free hosting provider
  let matchedFreeHosting: string | undefined;
  for (const [providerDomain, providerName] of Object.entries(FREE_HOSTING_PROVIDERS)) {
    if (sharedHost(cleanHostname) === providerDomain) {
      matchedFreeHosting = providerName;
      break;
    }
  }

  // 1. Is this an official canonical domain?
  const isOfficial = candidate.canonicalDomains.some(canonical =>
    cleanHostname === canonical || cleanHostname.endsWith('.' + canonical) || registeredDomain === canonical
  );

  if (!matchedFreeHosting && isOfficial) {
    return {
      candidate,
      isOfficial: true,
      isSubdomainAbuse: false,
      isFreeHostingAbuse: false,
      isCombosquat: false,
      details: `Official verified ${candidate.candidateName} domain (${cleanHostname}).`
    };
  }

  // 2. Unofficial domain with brand identity candidate
  if (matchedFreeHosting) {
    return {
      candidate,
      isOfficial: false,
      isSubdomainAbuse: true,
      isFreeHostingAbuse: true,
      isCombosquat: true,
      freeHostingProvider: matchedFreeHosting,
      details: `Page represents ${candidate.candidateName} hosted on third-party cloud platform (${matchedFreeHosting}) rather than official domain.`
    };
  }

  // 3. Generic Combosquat or Unrelated Registered Domain
  const isCombosquat = cleanHostname.includes(candidate.candidateName.toLowerCase().replace(/[^a-z0-9]/g, ''));
  return {
    candidate,
    isOfficial: false,
    isSubdomainAbuse: cleanHostname.split('.').length > 2,
    isFreeHostingAbuse: false,
    isCombosquat,
    details: `Page claims identity "${candidate.candidateName}" but is hosted on unrelated domain (${cleanHostname}).`
  };
}

/**
 * Legacy backwards-compatibility helper
 */
export function evaluateBrandImpersonation(
  hostname: string,
  pageTitle?: string,
  visibleTokens: string[] = [],
  formMeta?: FormAnalysisMetadata | null,
  socialMeta?: SocialEngineeringMetadata | null,
  customBrands: BrandIdentity[] = KNOWN_BRANDS
) {
  const candidate = inferBrandIdentity(hostname, pageTitle, visibleTokens, formMeta, socialMeta, customBrands);
  if (!candidate) return null;

  const evalResult = evaluateBrandDomainMismatch(hostname, candidate);
  if (!evalResult) return null;

  const matchedBrand: BrandIdentity = customBrands.find(b => b.name === candidate.candidateName) || {
    id: candidate.candidateName.toLowerCase().replace(/[^a-z0-9]/g, ''),
    name: candidate.candidateName,
    canonicalDomains: candidate.canonicalDomains,
    aliases: [candidate.candidateName],
    keywords: [candidate.candidateName.toLowerCase()],
    category: 'OTHER'
  };

  return {
    brand: matchedBrand,
    isOfficial: evalResult.isOfficial,
    isSubdomainAbuse: evalResult.isSubdomainAbuse,
    isFreeHostingAbuse: evalResult.isFreeHostingAbuse,
    isCombosquat: evalResult.isCombosquat,
    isHomoglyphOrTypo: false,
    freeHostingProvider: evalResult.freeHostingProvider,
    details: evalResult.details
  };
}
