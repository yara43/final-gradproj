import assert from 'node:assert/strict';
import { parseDomainHost } from '../extension/engine/domainParser.js';
import { extractUrlFeatures } from '../extension/engine/urlAnalysis.js';
import { extractRegisteredDomain } from '../extension/engine/brandIdentity.js';
import { decodePunycodeHostname } from '../extension/engine/idn.js';

const cases = [
  ['a.b.example.co.uk', 'example.co.uk', 2],
  ['accounts.google.com', 'google.com', 1],
  ['alice.github.io', 'alice.github.io', 0],
  ['bob.github.io', 'bob.github.io', 0],
  ['x.tenant.netlify.app', 'tenant.netlify.app', 1],
  ['team.pages.dev', 'team.pages.dev', 0],
  ['localhost', 'localhost', 0],
  ['192.0.2.1', '192.0.2.1', 0],
];

for (const [host, domain, depth] of cases) {
  const result = parseDomainHost(host);
  assert.equal(result.registeredDomain, domain, host);
  assert.equal(result.subdomainCount, depth, host);
  assert.equal(extractRegisteredDomain(host), domain, `brandIdentity: ${host}`);
  const { features } = extractUrlFeatures(`https://${host}/`);
  assert.equal(features.subdomainCount, depth, `urlAnalysis: ${host}`);
}

assert.notEqual(extractRegisteredDomain('alice.github.io'), extractRegisteredDomain('bob.github.io'));
const phishingDepth = extractUrlFeatures('https://login.paypal.com.attacker.co.uk/');
assert.equal(phishingDepth.features.subdomainCount, 3);
assert.ok(phishingDepth.signals.some(signal => signal.id === 'SIGNAL_EXCESSIVE_SUBDOMAINS'));
assert.equal(decodePunycodeHostname('xn--bcher-kva.example'), 'bücher.example');
assert.equal(decodePunycodeHostname('xn--e1afmkfd.xn--p1ai'), 'пример.рф');

const unicodeHost = extractUrlFeatures('https://bücher.example/login');
assert.equal(unicodeHost.features.hostname, 'xn--bcher-kva.example');
assert.equal(unicodeHost.features.decodedPunycode, 'bücher.example');
assert.equal(unicodeHost.features.hasNonAsciiInHost, true);
assert.ok(unicodeHost.signals.some(signal => signal.id === 'SIGNAL_PUNYCODE_IDN'));
assert.ok(!unicodeHost.signals.some(signal => signal.id === 'SIGNAL_NON_ASCII_DOMAIN'));

const loopback = extractUrlFeatures('http://[::1]/');
assert.equal(loopback.features.isIpAddress, true);
assert.ok(!loopback.signals.some(signal => signal.id === 'SIGNAL_IP_HOST'));
assert.ok(!loopback.signals.some(signal => signal.id === 'SIGNAL_INSECURE_HTTP'));
assert.ok(extractUrlFeatures('https://[2001:db8::1]/').signals.some(signal => signal.id === 'SIGNAL_IP_HOST'));

assert.ok(extractUrlFeatures('https://paypal.com@attacker.example/').signals.some(signal => signal.id === 'SIGNAL_USERINFO_SPOOF'));
assert.ok(!extractUrlFeatures('https://attacker.example/path@paypal.com').signals.some(signal => signal.id === 'SIGNAL_USERINFO_SPOOF'));
console.log('Public Suffix List domain tests passed.');
