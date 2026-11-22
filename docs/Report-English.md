# PhishGuard: Brand impersonation change report
## 1. What decision are we making?
A publisher can write “How to use Facebook” and ask readers to sign in to the newspaper. That does not make the newspaper Facebook. A password form on that same domain explicitly asking readers to “Sign in to Facebook” makes a different claim. The detector compares the claimed identity with the hostname. A mismatch is evidence to investigate, not proof that credentials were stolen.
## 2. From page to decision
Chrome runs extension/content/contentScript.js inside the page. It groups structural labels by form and reports whether that form contains a password or verification-code field. It does not need the user's typed password. The background service worker passes the observations to the scoring engine. src/core/engine/brandIdentity.ts is the identity source; extension/engine/brandIdentity.js is the JavaScript Chrome loads. The scoring engine combines that result with separate form, URL and payment signals.
## 3. What changed and why?
1. Article versus login claim. Previously, a document-wide mention could combine with an unrelated password field. A scoped credential form now supplies its own labels, such as “Sign in to Facebook”. The collector and decision engine both had to change: a page-wide boolean cannot identify which form made a claim.
2. Payment methods. An isolated PayPal subheading under “Payment methods” is recorded as a mention rather than used by itself to establish impersonation. Exact page-title claims and explicit login labels still carry separate weight.
3. Owner versus mention. A Facebook-hosted post titled “PayPal” retains Meta as the domain owner and records PayPal as a mentioned brand. A competing explicit credential-form claim can take priority without losing the owner. Reversing the registry no longer changes the tested result.
4. Unknown organizations. A student portal title is not evidence of a matching dot-com registration. The engine now abstains when no registry evidence supports a candidate. Other detectors still run. In the generic checkout fixture, the score fell to 25: card collection remained visible, but the fabricated brand allegation disappeared. We updated this fixture's expectation and separately asserted both the presence of the financial signal and the absence of brand signals.
5. X / Twitter. Both official domains are registered. An isolated X on an unrelated page is too ambiguous, whereas “Sign in to X” inside a credential form supplies meaningful context.
6. Shared static hosting. A hosting provider owns its platform, not the identity claimed by every tenant. On demo.github.io, the detector separates demo from github.io. It neither grants official GitHub status nor treats the provider suffix as a tenant brand token. The same logic covers listed providers such as Netlify and Vercel. Ordinary hosted portfolios can remain unflagged; a known-brand claim on an unrelated tenant can produce a hosting mismatch.
## 4. Dependent changes
The form metadata type, DOM extractor and content script now carry per-form labels. Page events consume the same evidence as scoring. The worker now supplies the object signatures expected by the event builders, records events through recordEvent, and supplies analysis in the content-script response. Risk scoring no longer applies the official-domain discount to a competing identity claim. The typosquatting module also excludes recognized provider suffixes so a second detector does not reintroduce the trust error.
## 5. Validation and limits
From the project root run node scripts/test-brand-review.mjs with Node 24. Ten regression groups passed; all 18 project scenarios passed with the documented checkout expectation change. Coverage includes unrelated and branded forms, payment mentions, reversed registry order, unknown portals, X, hosted sites, and metadata messages through a mocked Chrome worker. This was not a live-browser or performance test. Text rules and the provider and brand registries are finite; logo-only claims and unrecognized wording can be missed. The existing allowlist can short-circuit scoring before the brand engine runs.

## 6. Actual source excerpts: before and after
**Before — upstream 348f3be:**
~~~ts
const isCanonical = brand.canonicalDomains.some(d => cleanHostname === d || cleanHostname.endsWith('.' + d));
if (pageTitle && (pageTitle.toLowerCase().includes(brand.name.toLowerCase()) || brand.keywords.some(k => pageTitle.toLowerCase().includes(k)))) {
if (visibleTokens.some(t => t.toLowerCase() === brand.name.toLowerCase() || brand.keywords.includes(t.toLowerCase()))) {
if (pageTitle && pageTitle.trim().length > 2) {
const inferredCanonical = `${inferredClean}.com`;
~~~
**After — local implementation:**
~~~ts
const tenant = provider ? host.slice(0, -(provider.length + 1)) : host;
const labels = (formMeta?.suspiciousForms || []).filter(f => f.hasPasswordField || f.has2FAField).flatMap(f => f.identityLabels || []).map(norm);
const formClaim = labels.some(t => names.some(n => login(t,n) || (n.length > 1 && t === n)));
const titleClaim = names.some(n => login(title,n) || (n.length > 1 && title === n));
const official = !provider && brand.canonicalDomains.some(d => host === d || host.endsWith('.'+d));
const owner = rows.find(r => r.official);
const row = rows.find(r => r.formClaim && r !== owner) || owner || rows.find(r => r.formClaim) || rows.find(r => r.titleClaim) || rows.find(r => r.hostMatch);
if (!row) return null; // Unknown identity: no verified domain to compare against.
~~~
Read in order: tenant isolates the hosted name; labels selects credential-form text; formClaim and titleClaim assess identity evidence; official and owner establish domain ownership; row chooses the candidate; null abstains. [Full line-by-line diff](before-after.diff): minus marks removed lines and plus marks additions.
