import { parse } from 'tldts';

/**
 * Public Suffix List based hostname parsing. Include private suffixes so two
 * different tenants on github.io, netlify.app, or pages.dev stay separate.
 */
export function parseDomainHost(hostname: string) {
  const host = hostname.trim().toLowerCase().replace(/\.$/, '');
  const result = parse(host, { allowPrivateDomains: true });

  return {
    registeredDomain: result.domain || host,
    publicSuffix: result.publicSuffix,
    subdomainCount: result.subdomain ? result.subdomain.split('.').filter(Boolean).length : 0
  };
}
